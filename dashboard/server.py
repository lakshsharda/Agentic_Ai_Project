"""Phase 5 dashboard backend: a passive, read-only view over the incident store.

Not an A2A system and not a seventh agent: it holds no state, makes no calls to
the six systems, and exposes no write or approval action (Decision 5). Approvals
stay with ``scripts/comms_signoff.py`` and the Comms ``/signoff`` endpoint; the
dashboard only *shows* that a draft is waiting and how to sign it off.

    GET /                              the single-page frontend
    GET /health                        liveness + whether the store answers
    GET /incidents                     incidents: id, status, severity, created/updated
    GET /incidents/{id}/timeline       one incident's story: trace_events merged with its
                                       status_history and comms_drafts, ordered by time
    GET /live?limit=N                  the newest N trace events across all incidents

FastAPI because the six systems already use it and it is installed in the existing
venvs; Flask would add a dependency for nothing. Runs from ``.venv-crew``.

Every string leaving this service is scrubbed (shared.trace.scrub_text): no attacker
IP or internal host is ever returned, and draft *text* is never returned at all
(a REJECTED draft may legitimately hold the very text the validator refused).

    .venv-crew\\Scripts\\python -m dashboard.server        # http://127.0.0.1:8090
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psycopg
import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from psycopg.rows import dict_row

from shared.llm import load_project_env
from shared.store.incidents import store_dsn
from shared.trace import scrub_detail, scrub_text

logger = logging.getLogger("dashboard")

DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8090"))
STATIC_DIR = Path(__file__).resolve().parent / "static"
_CONNECT_TIMEOUT = 3
_LIVE_MAX = 500

SIGNOFF_HINT = (
    "Approve or reject through the existing paths -- this dashboard is read-only: "
    ".venv-app\\Scripts\\python scripts\\comms_signoff.py approve <draft_id> --as <you>   "
    "or POST /signoff on the Customer Comms service (port 9106)"
)


class StoreUnavailable(Exception):
    pass


def _iso(v: Any) -> Any:
    """Every timestamp leaves this service as UTC ISO-8601, so trace rows (timestamptz, returned in
    the session's zone) and status_history entries (UTC strings) sort and compare correctly."""
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()
    return v


def _utc(s: Any) -> str:
    """Normalise a stored ISO string (any offset) to UTC; unparseable values pass through."""
    try:
        return _iso(datetime.fromisoformat(str(s)))
    except (TypeError, ValueError):
        return s or ""


def _query(sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    try:
        with psycopg.connect(store_dsn(), row_factory=dict_row, connect_timeout=_CONNECT_TIMEOUT) as conn:
            return conn.execute(sql, params).fetchall()
    except psycopg.Error as exc:
        raise StoreUnavailable(type(exc).__name__) from exc


def _trace_row(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": "trace",
        "event_id": r["event_id"],
        "incident_id": r["incident_id"],
        "ts": _iso(r["timestamp"]),
        "from_system": r["from_system"],
        "to_system": r["to_system"],
        "event_type": r["event_type"],
        "decision": r["decision"],
        "summary": scrub_text(r["summary"]),
        "detail": scrub_detail(r["detail"]),
    }


def _unavailable() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"ok": False, "error": "incident store unreachable",
                 "hint": "check that Postgres is running on the configured port; the dashboard retries on the next refresh"},
    )


def build_app() -> FastAPI:
    app = FastAPI(title="Crisis dashboard (read-only)")

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/health")
    async def health():
        try:
            _query("SELECT 1")
            return {"status": "ok", "store": "up", "read_only": True}
        except StoreUnavailable:
            return JSONResponse(status_code=200, content={"status": "ok", "store": "down", "read_only": True})

    @app.get("/incidents")
    async def incidents(limit: int = 50):
        limit = max(1, min(limit, 200))
        try:
            rows = _query(
                "SELECT incident_id, status, severity, incident_type, escalated, created_at, updated_at "
                "FROM incidents ORDER BY created_at DESC LIMIT %s", (limit,))
            pending = _query(
                "SELECT incident_id, count(*) AS n FROM comms_drafts WHERE status = 'PENDING_SIGNOFF' "
                "GROUP BY incident_id")
        except StoreUnavailable:
            return _unavailable()
        pend = {p["incident_id"]: p["n"] for p in pending}
        return {"ok": True, "count": len(rows), "incidents": [
            {"incident_id": r["incident_id"], "status": r["status"], "severity": r["severity"],
             "incident_type": scrub_text(r["incident_type"]) if r["incident_type"] else None,
             "escalated": r["escalated"], "created_at": _iso(r["created_at"]),
             "updated_at": _iso(r["updated_at"]),
             "pending_signoff": pend.get(r["incident_id"], 0)} for r in rows]}

    @app.get("/incidents/{incident_id}/timeline")
    async def timeline(incident_id: str):
        try:
            inc = _query("SELECT incident_id, status, severity, incident_type, escalated, created_at, "
                         "updated_at, raw_payload FROM incidents WHERE incident_id = %s", (incident_id,))
            traces = _query('SELECT * FROM trace_events WHERE incident_id = %s '
                            'ORDER BY "timestamp", event_id', (incident_id,))
            drafts = _query(
                "SELECT draft_id, event_type, severity_at_draft, status, approved_by, generation, "
                "created_at, decided_at, published_at, publish_channel, sent, edited_by_human "
                "FROM comms_drafts WHERE incident_id = %s ORDER BY created_at", (incident_id,))
        except StoreUnavailable:
            return _unavailable()

        items: List[Dict[str, Any]] = [_trace_row(r) for r in traces]

        # status_history: keep the entries the trace did not already cover. A lifecycle move is
        # "covered" when a status_advanced trace row names the same transition.
        covered = {t["summary"] for t in items if t["event_type"] == "status_advanced"}
        # Comms writes both a trace row and a status_history entry for the same draft moment.
        comms_pairs = {"comms_draft_created": "draft_created", "comms_signoff": "signoff_recorded",
                       "comms_published": "published"}
        covered_draft = {(t["event_type"], (t["detail"] or {}).get("draft_id")) for t in items}
        history = ((inc[0]["raw_payload"] or {}).get("status_history") or []) if inc else []
        for h in history:
            if "to" in h and "event" not in h:
                if scrub_text(f"{h.get('from')} -> {h['to']}") in covered:
                    continue
                summary, etype = f"{h.get('from')} -> {h['to']}", "status_advanced"
            else:
                ev = h.get("event", "history")
                if ev in comms_pairs and (comms_pairs[ev], h.get("draft_id")) in covered_draft:
                    continue
                summary, etype = scrub_text(ev), "history"
            items.append({
                "source": "status_history", "event_id": None, "incident_id": incident_id,
                "ts": _utc(h.get("at")), "from_system": scrub_text(h.get("by")), "to_system": None,
                "event_type": etype, "decision": "n/a", "summary": scrub_text(summary),
                "detail": scrub_detail({k: v for k, v in h.items()
                                        if k in ("draft_id", "comms_event", "decision", "channel", "sent")}),
            })

        draft_meta = []
        for d in drafts:
            draft_meta.append({k: _iso(v) for k, v in d.items()})  # no draft_text, by design

        items.sort(key=lambda i: (datetime.fromisoformat(i["ts"]) if i["ts"] else datetime.min.replace(tzinfo=timezone.utc),
                                  i["event_id"] or 0))
        current = ({"incident_id": inc[0]["incident_id"], "status": inc[0]["status"],
                    "severity": inc[0]["severity"],
                    "incident_type": scrub_text(inc[0]["incident_type"]) if inc[0]["incident_type"] else None,
                    "escalated": inc[0]["escalated"], "created_at": _iso(inc[0]["created_at"]),
                    "updated_at": _iso(inc[0]["updated_at"])} if inc else None)
        pending = [d for d in draft_meta if d["status"] == "PENDING_SIGNOFF"]
        return {"ok": True, "incident": current, "events": items, "drafts": draft_meta,
                "pending_signoff": pending, "signoff_hint": SIGNOFF_HINT if pending else None}

    @app.get("/live")
    async def live(limit: int = 50):
        limit = max(1, min(limit, _LIVE_MAX))
        try:
            rows = _query('SELECT * FROM trace_events ORDER BY "timestamp" DESC, event_id DESC LIMIT %s',
                          (limit,))
        except StoreUnavailable:
            return _unavailable()
        return {"ok": True, "count": len(rows), "events": [_trace_row(r) for r in rows]}

    return app


app = build_app()


def main() -> None:
    load_project_env()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    uvicorn.run(app, host="127.0.0.1", port=DASHBOARD_PORT, log_level="warning")


if __name__ == "__main__":
    main()
