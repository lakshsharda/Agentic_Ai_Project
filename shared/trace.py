"""Unified trace log: one helper every system calls as it acts.

``record_trace(...)`` appends a row to the ``trace_events`` table in the incident
store. It is LOGGING, never control flow (Phase 5, decision 4):

* it never raises -- every failure degrades to a rate-limited warning;
* it never blocks -- the call only timestamps the event and puts it on a bounded
  in-memory queue; a single daemon thread does the database write, so a slow or
  dead store cannot stall an async server's event loop or hold up the action;
* it never reads the table back or influences a decision.

If the queue is full (store down for a long time) new events are dropped with a
warning rather than growing memory or waiting.

Privacy: ``summary`` and ``detail`` are scrubbed before they are queued, with the
same rules as the Phase 4 customer-text validator -- IPv4/IPv6 addresses and
internal hostnames are replaced by ``[ip]`` / ``[host]``, free-text blobs and
known-sensitive keys are dropped from ``detail``. Callers should still not pass
attacker detail in; the scrubber is the backstop, not the plan.

Event types in use (free text in the table, documented here):

    a2a_sent / a2a_received / a2a_failed     an envelope crossed the wire
    reclassify_sent / reclassify_received    the Forensics -> Threat Assessment feedback loop
    authority_checked / authority_denied     every check_authority() call
    gate_evaluated                           evaluate_action_gate / evaluate_publish_gate
    approval_recorded                        On-Call's human ack or timeout auto-approval
    evidence_preserved                       Forensics' evidence signal (Containment's second gate)
    status_advanced                          an incident lifecycle move (incl. creation)
    action_executed                          a real side effect (block, lift, page)
    draft_created / signoff_recorded / signoff_refused / published   Customer Comms

Decisions: ``auto`` (cleared by policy), ``human`` (a person cleared it),
``timeout_escalation`` (On-Call's timer cleared it), ``blocked`` (refused or
still held), ``n/a`` (not a decision).
"""

from __future__ import annotations

import atexit
import logging
import os
import queue
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg
from psycopg.types.json import Jsonb

from shared.comms_validation import _INTERNAL_HOST, _IPV4, _IPV6

logger = logging.getLogger(__name__)

DECISIONS = ("auto", "human", "timeout_escalation", "blocked", "n/a")

_QUEUE_MAX = 5000
_CONNECT_TIMEOUT = 3
_WARN_EVERY_SECONDS = 30.0
# After a failed write the writer stops trying for this long and drops what arrives meanwhile.
# Without it a dead store (each attempt can take seconds to time out) would back the queue up
# behind the writer; for logging, losing a few seconds of events beats unbounded lag.
_COOLDOWN_SECONDS = 3.0
_MAX_STR = 300
_MAX_DETAIL_KEYS = 20

# Keys whose values are free text or attacker-derived by nature: never stored.
_DROP_KEYS = {
    "text", "draft_text", "original_text", "edited_text", "evidence", "usernames", "username",
    "blocked_ips", "unblocked", "ips", "ip", "source_ip", "top_failed_login_ips",
    "top_targeted_usernames", "narrative", "root_cause_narrative", "plan", "rationale", "reason_text",
}

# Containment re-evaluates its gate on a poll while it waits. Identical *routine* rows from the same
# process within this window are collapsed so the timeline shows state changes, not a heartbeat.
# Denials and every other event type are never collapsed.
_DEDUPE_TYPES = {"gate_evaluated", "authority_checked"}
_DEDUPE_WINDOW = 20.0
_seen: Dict[tuple, float] = {}

_queue: "queue.Queue[tuple]" = queue.Queue(maxsize=_QUEUE_MAX)
_worker_lock = threading.Lock()
_worker: Optional[threading.Thread] = None
_last_warn = 0.0
_dropped = 0


def trace_dsn() -> str:
    """Where trace rows go. ``TRACE_STORE_DSN`` overrides the incident store's DSN
    (used to prove the degrade-to-warning behavior against a bad connection)."""
    override = os.environ.get("TRACE_STORE_DSN")
    if override:
        return override
    from shared.store.incidents import store_dsn  # lazy: the store imports this module

    return store_dsn()


# --------------------------------------------------------------------------
# Scrubbing
# --------------------------------------------------------------------------


def scrub_text(text: Any) -> str:
    """Replace IPs and internal hostnames, trim length. Always returns a str."""
    s = "" if text is None else str(text)
    s = _IPV4.sub("[ip]", s)
    s = _IPV6.sub("[ip]", s)
    s = _INTERNAL_HOST.sub("[host]", s)
    return s if len(s) <= _MAX_STR else s[: _MAX_STR - 1] + "…"


def _scrub_value(v: Any, depth: int = 0) -> Any:
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, str):
        return scrub_text(v)
    if depth >= 2:
        return scrub_text(v)
    if isinstance(v, dict):
        return scrub_detail(v, depth + 1)
    if isinstance(v, (list, tuple, set)):
        return [_scrub_value(x, depth + 1) for x in list(v)[:10]]
    return scrub_text(getattr(v, "value", v))


def scrub_detail(detail: Optional[Dict[str, Any]], depth: int = 0) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (detail or {}).items():
        if str(k).lower() in _DROP_KEYS:
            continue
        out[scrub_text(k)[:60]] = _scrub_value(v, depth)
        if len(out) >= _MAX_DETAIL_KEYS:
            break
    return out


def _sys(v: Any) -> Optional[str]:
    if v is None:
        return None
    return str(getattr(v, "value", v))


# --------------------------------------------------------------------------
# Writer
# --------------------------------------------------------------------------


def _warn(msg: str, *args: Any) -> None:
    """Rate-limited so a dead store does not flood the logs."""
    global _last_warn
    now = time.monotonic()
    if now - _last_warn >= _WARN_EVERY_SECONDS:
        _last_warn = now
        logger.warning(msg, *args)


def _insert(conn: psycopg.Connection, row: tuple) -> None:
    conn.execute(
        'INSERT INTO trace_events (incident_id, "timestamp", from_system, to_system, event_type, '
        "decision, summary, detail) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (row[0], row[1], row[2], row[3], row[4], row[5], row[6], Jsonb(row[7])),
    )


def _run_worker() -> None:
    global _dropped
    conn: Optional[psycopg.Connection] = None
    conn_dsn: Optional[str] = None
    down_until = 0.0
    while True:
        row = _queue.get()
        try:
            if time.monotonic() < down_until:
                _dropped += 1
                continue
            dsn = trace_dsn()
            if conn is None or conn.closed or dsn != conn_dsn:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass
                conn = psycopg.connect(dsn, autocommit=True, connect_timeout=_CONNECT_TIMEOUT)
                conn_dsn = dsn
            _insert(conn, row)
        except Exception as exc:  # noqa: BLE001 - tracing must never raise
            _warn("trace write failed (%s: %s); the action it describes is unaffected",
                  type(exc).__name__, str(exc).splitlines()[0][:120] if str(exc) else "")
            try:
                if conn is not None:
                    conn.close()
            except Exception:  # noqa: BLE001
                pass
            conn = None
            down_until = time.monotonic() + _COOLDOWN_SECONDS
        finally:
            _queue.task_done()


def _ensure_worker() -> None:
    global _worker
    if _worker is not None and _worker.is_alive():
        return
    with _worker_lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_run_worker, name="trace-writer", daemon=True)
            _worker.start()


def record_trace(
    *,
    from_system: Any,
    event_type: str,
    incident_id: Optional[str] = None,
    to_system: Any = None,
    decision: str = "n/a",
    summary: str = "",
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    """Queue one trace event. Never raises, never blocks."""
    global _dropped
    try:
        if os.environ.get("TRACE_DISABLED") == "1":      # kill switch: lets a run prove tracing is not involved
            return
        if decision not in DECISIONS:
            decision = "n/a"
        row = (
            incident_id,
            datetime.now(timezone.utc),
            _sys(from_system) or "unknown",
            _sys(to_system),
            str(event_type)[:60],
            decision,
            scrub_text(summary),
            scrub_detail(detail),
        )
        if row[4] in _DEDUPE_TYPES:
            key = (row[0], row[2], row[3], row[4], row[5], row[6])
            now = time.monotonic()
            if now - _seen.get(key, -1e9) < _DEDUPE_WINDOW:
                return
            if len(_seen) > 2000:
                _seen.clear()
            _seen[key] = now
        _ensure_worker()
        _queue.put_nowait(row)
    except queue.Full:
        _dropped += 1
        _warn("trace queue full; dropping events (%d dropped so far) -- the actions are unaffected", _dropped)
    except Exception as exc:  # noqa: BLE001 - tracing must never raise
        _warn("trace event could not be queued (%s: %s)", type(exc).__name__, exc)


def flush(timeout: float = 5.0) -> bool:
    """Wait until queued events have been attempted. For tests and clean shutdown."""
    deadline = time.monotonic() + timeout
    while _queue.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.02)
    return _queue.unfinished_tasks == 0


atexit.register(lambda: flush(2.0))


def pending() -> int:
    """Events queued but not yet written (diagnostics)."""
    return _queue.unfinished_tasks
