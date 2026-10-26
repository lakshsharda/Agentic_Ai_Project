"""Live reasoning feed writer: what each agent actually said, unsanitized, for the internal demo view.

``record_reasoning(...)`` appends a row to ``reasoning_events``. It mirrors ``shared/trace.py`` on
purpose -- the same never-raises, never-blocks pattern (Phase 5, decision 4):

* it never raises: every failure degrades to a rate-limited warning;
* it never blocks: the call timestamps the event and puts it on a bounded queue, and one daemon
  thread does the database write, so a slow or dead store cannot hold up an agent;
* it never reads the table back or influences a decision.

It differs in exactly one way, and that is the point of the module (Phase 6, decision 2): there is NO
scrubbing. The text is stored as the model wrote it, real attacker IPs and usernames included, so a
viewer can see the reasoning is grounded in real data. That is why this is a separate table, a
separate writer and a separate view from the scrubbed ``trace_events`` audit trail. Nothing here
may be copied into ``shared/trace.py``'s path, and ``shared/trace.py``'s scrubber must not be
loosened to make room for it.

Phase 6.1 adds a narration layer, additive only: each entry may carry a one-line plain-English ``narration``
the caller derived from variables it already holds (never a model call), plus ``caused_by``/``depth`` taken
from the static causal map in ``shared/narration.py`` so the viewer can draw the chain as a story.

Phase 6.2 adds a two-step write, additive only (decision 3): ``start_call(...)`` writes an ``in_progress``
row -- agent, system, incident, a "<agent> is thinking..." placeholder -- *before* the model call is made,
so a live viewer sees the call start. The ``CallHandle`` it returns is then resolved with
``.resolve(text=..., narration=...)`` once the model answers (flips the same row to ``resolved``, fills in
the real text/narration and, best-effort, the ``served_by`` model tag -- see ``shared.llm``'s capture
helpers) or ``.fail(reason=...)`` if the call raised, so the feed never shows a permanently-stuck
"thinking" card. ``record_reasoning(...)`` is unchanged and keeps writing a single already-resolved row,
for the entries that are not themselves bracketing one call (e.g. Detection's post-hoc handoff write).

``REASONING_STORE_DSN`` overrides the store (used to prove the degrade-to-warning behavior);
``REASONING_DISABLED=1`` turns the writer off entirely.
"""

from __future__ import annotations

import atexit
import logging
import os
import queue
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg

from shared.narration import chain_for

logger = logging.getLogger(__name__)

_QUEUE_MAX = 2000
_CONNECT_TIMEOUT = 3
_WARN_EVERY_SECONDS = 30.0
_COOLDOWN_SECONDS = 3.0
_MAX_TEXT = 20000           # a root-cause narrative is a few hundred words; this is a safety cap only

# Queue items are (op, payload) pairs so one worker/one queue serves both the plain one-shot writer and
# the two-step start/resolve writer. FIFO order is what makes the latter safe: a resolve for call_id X is
# only ever queued by code that already called start_call() for X, on the same call stack, so its queue
# item is always enqueued after X's insert -- the single worker thread drains them in that same order.
_OP_INSERT = "insert"
_OP_INSERT_CALL = "insert_call"
_OP_UPDATE_CALL = "update_call"

_queue: "queue.Queue[tuple]" = queue.Queue(maxsize=_QUEUE_MAX)
_worker_lock = threading.Lock()
_worker: Optional[threading.Thread] = None
_last_warn = 0.0
_dropped = 0


def reasoning_dsn() -> str:
    override = os.environ.get("REASONING_STORE_DSN")
    if override:
        return override
    from shared.store.incidents import store_dsn  # lazy: keeps this module import-light

    return store_dsn()


def _sys(v: Any) -> str:
    return str(getattr(v, "value", v)) if v is not None else "unknown"


def _warn(msg: str, *args: Any) -> None:
    global _last_warn
    now = time.monotonic()
    if now - _last_warn >= _WARN_EVERY_SECONDS:
        _last_warn = now
        logger.warning(msg, *args)


_SQL = {
    _OP_INSERT: (
        'INSERT INTO reasoning_events (incident_id, "timestamp", system, agent_name, reasoning_text, '
        "narration, caused_by, depth, status, resolved_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'resolved', %s)"
    ),
    _OP_INSERT_CALL: (
        'INSERT INTO reasoning_events (incident_id, "timestamp", system, agent_name, reasoning_text, '
        "narration, caused_by, depth, call_id, status) "
        "VALUES (%s, %s, %s, %s, '', %s, %s, %s, %s, 'in_progress')"
    ),
    _OP_UPDATE_CALL: (
        "UPDATE reasoning_events SET reasoning_text = %s, narration = %s, served_by = %s, "
        "status = %s, resolved_at = %s WHERE call_id = %s AND status = 'in_progress'"
    ),
}


def _run_worker() -> None:
    global _dropped
    conn: Optional[psycopg.Connection] = None
    conn_dsn: Optional[str] = None
    down_until = 0.0
    while True:
        op, row = _queue.get()
        try:
            if time.monotonic() < down_until:
                _dropped += 1
                continue
            dsn = reasoning_dsn()
            if conn is None or conn.closed or dsn != conn_dsn:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass
                conn = psycopg.connect(dsn, autocommit=True, connect_timeout=_CONNECT_TIMEOUT)
                conn_dsn = dsn
            conn.execute(_SQL[op], row)
        except Exception as exc:  # noqa: BLE001 - the reasoning feed must never raise
            _warn("reasoning write failed (%s: %s); the action it describes is unaffected",
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
            _worker = threading.Thread(target=_run_worker, name="reasoning-writer", daemon=True)
            _worker.start()


def record_reasoning(*, system: Any, agent_name: str, text: Any, incident_id: Optional[str] = None,
                     narration: Optional[str] = None) -> None:
    """Queue one reasoning entry. Never raises, never blocks. NOT scrubbed -- internal demo view only.

    ``narration``: optional one-line plain-English summary built by the caller from data it already has."""
    global _dropped
    try:
        if os.environ.get("REASONING_DISABLED") == "1":
            return
        body = "" if text is None else str(text).strip()
        if not body:
            return
        name = str(agent_name)[:80]
        caused_by, depth = chain_for(name)
        line = " ".join(str(narration).split())[:400] if narration else None
        now = datetime.now(timezone.utc)
        row = (incident_id, now, _sys(system), name, body[:_MAX_TEXT], line, caused_by, depth, now)
        _ensure_worker()
        _queue.put_nowait((_OP_INSERT, row))
    except queue.Full:
        _dropped += 1
        _warn("reasoning queue full; dropping entries (%d dropped so far) -- the actions are unaffected", _dropped)
    except Exception as exc:  # noqa: BLE001
        _warn("reasoning entry could not be queued (%s: %s)", type(exc).__name__, exc)


class CallHandle:
    """A reasoning entry whose row already exists as 'in_progress'. Resolve it (or fail it) once the
    model call it represents returns. Never raises -- same contract as record_reasoning."""

    __slots__ = ("call_id", "_system", "_agent_name", "_incident_id", "_served_token", "_live")

    def __init__(self, call_id: str, system: Any, agent_name: str, incident_id: Optional[str], served_token: Any,
                live: bool) -> None:
        self.call_id = call_id
        self._system = system
        self._agent_name = agent_name
        self._incident_id = incident_id
        self._served_token = served_token
        self._live = live  # False if the start row was never actually queued (e.g. REASONING_DISABLED)

    def _served_by(self, explicit: Optional[str]) -> Optional[str]:
        if explicit:
            return explicit
        try:
            from shared.llm import served_capture_read

            return served_capture_read()
        except Exception:  # noqa: BLE001 - best-effort only; shared.llm may not even be importable here
            return None

    def _stop_capture(self) -> None:
        if self._served_token is not None:
            try:
                from shared.llm import served_capture_stop

                served_capture_stop(self._served_token)
            except Exception:  # noqa: BLE001
                pass
            self._served_token = None

    def resolve(self, *, text: Any, narration: Optional[str] = None, served_by: Optional[str] = None) -> None:
        """Call once the model call answers. Flips the row to 'resolved' with the real text/narration
        and, if known, the served_by model tag (read from shared.llm's capture unless passed explicitly)."""
        served = self._served_by(served_by)
        self._stop_capture()
        if not self._live:
            return
        try:
            body = "" if text is None else str(text).strip()
            line = " ".join(str(narration).split())[:400] if narration else None
            now = datetime.now(timezone.utc)
            row = (body[:_MAX_TEXT], line, (served or None), "resolved", now, self.call_id)
            _ensure_worker()
            _queue.put_nowait((_OP_UPDATE_CALL, row))
        except queue.Full:
            _warn("reasoning queue full; could not resolve call %s", self.call_id)
        except Exception as exc:  # noqa: BLE001
            _warn("reasoning call could not be resolved (%s: %s)", type(exc).__name__, exc)

    def fail(self, *, reason: str) -> None:
        """Call if the model call raised, so the feed shows a clear failure instead of staying stuck on
        'thinking...' forever. Does not swallow the original exception -- callers still re-raise."""
        self._stop_capture()
        if not self._live:
            return
        try:
            narration = f"{self._agent_name} call failed ({reason}); the action it would have driven did not run."
            now = datetime.now(timezone.utc)
            row = (f"(call failed: {reason})", narration, None, "failed", now, self.call_id)
            _ensure_worker()
            _queue.put_nowait((_OP_UPDATE_CALL, row))
        except queue.Full:
            _warn("reasoning queue full; could not record failed call %s", self.call_id)
        except Exception as exc:  # noqa: BLE001
            _warn("reasoning call-failure could not be queued (%s: %s)", type(exc).__name__, exc)


def start_call(*, system: Any, agent_name: str, incident_id: Optional[str] = None,
               narration: Optional[str] = None) -> CallHandle:
    """Write an 'in_progress' reasoning row now, before the model call is made, so a live viewer sees
    "<agent> is thinking..." immediately (Phase 6.2, decision 3). Returns a CallHandle; call its
    .resolve() (or .fail()) once the call returns. Never raises, never blocks -- if the write cannot be
    queued, the handle still works, it just has nothing to resolve.

    Call this right before the awaited/to_thread call it describes, and resolve it right after, exactly
    where record_reasoning(...) used to sit -- the bracket is the whole point."""
    name = str(agent_name)[:80]
    call_id = uuid.uuid4().hex
    served_token = None
    live = False
    try:
        if os.environ.get("REASONING_DISABLED") != "1":
            try:
                from shared.llm import served_capture_start

                served_token = served_capture_start()
            except Exception:  # noqa: BLE001 - served_by capture is optional
                served_token = None
            caused_by, depth = chain_for(name)
            line = " ".join(str(narration).split())[:400] if narration else f"{name} is thinking..."
            now = datetime.now(timezone.utc)
            row = (incident_id, now, _sys(system), name, line, caused_by, depth, call_id)
            _ensure_worker()
            _queue.put_nowait((_OP_INSERT_CALL, row))
            live = True
    except queue.Full:
        _warn("reasoning queue full; call %s will not show as in-progress", call_id)
    except Exception as exc:  # noqa: BLE001
        _warn("reasoning call could not be started (%s: %s)", type(exc).__name__, exc)
    return CallHandle(call_id, system, name, incident_id, served_token, live)


def flush(timeout: float = 5.0) -> bool:
    """Wait until queued entries have been attempted. For tests and clean shutdown."""
    deadline = time.monotonic() + timeout
    while _queue.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.02)
    return _queue.unfinished_tasks == 0


atexit.register(lambda: flush(2.0))


def pending() -> int:
    return _queue.unfinished_tasks
