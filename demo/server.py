"""Phase 6 internal demo backend: the live log tail and the live agent-reasoning feed.

    GET /                       landing page linking the internal views
    GET /logs                   live tail of the target app's access.log (browser tab)
    GET /reasoning              live agent-reasoning feed (browser tab)
    GET /stream/logs            Server-Sent Events: new access.log lines, as they are written
    GET /stream/reasoning       Server-Sent Events: new reasoning_events rows, in time order (an
                                in_progress row is re-sent, same event_id, when it resolves/fails)
    GET /reasoning/events       the same rows as plain JSON (?after=<event_id>&limit=N&incident_id=
                                &in_flight=<comma-separated event_ids still being watched for a transition>)
    GET /incidents/scope        Phase 6.2 Task 2: incidents a view can scope to -- id, status, created_at,
                                and the source IPs its own evidence names (?limit=N)
    GET /health

INTERNAL DEMO USE ONLY -- UNSANITIZED. This process shows raw attacker IPs, usernames and the full
text the models wrote. It is a separate process on a separate port (:8091) from the Phase 5 trace
dashboard (:8090) on purpose: the :8090 dashboard is the scrubbed, audit-grade view and must stay
exactly that, so nothing unsanitized is ever served from it. Every page here carries a banner that
says so. Read-only, local only, no authentication (a known limitation of the demo tool).

Why a second small backend rather than reusing :8090: the log tail and the reasoning feed are the
two unscrubbed views; putting them behind the audit dashboard's port would blur the one rule that
matters this phase. Why SSE rather than websockets: one-directional, plain HTTP, works with the
browser's built-in EventSource and needs no extra dependency.

The log tail reuses ``target_app/logs/access.log`` exactly as it is; it only reads the file.

    .venv-crew\\Scripts\\python -m demo.server        # http://127.0.0.1:8091
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psycopg
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from psycopg.rows import dict_row

from shared.llm import load_project_env
from shared.narration import chain_for, is_parallel
from shared.store.incidents import store_dsn

logger = logging.getLogger("demo")

DEMO_PORT = int(os.environ.get("DEMO_PORT", "8091"))
STATIC_DIR = Path(__file__).resolve().parent / "static"
ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = Path(os.environ.get("TARGET_APP_LOG_DIR", ROOT / "target_app" / "logs")) / "access.log"

LOG_POLL_SECONDS = 0.2          # a new line shows up well inside the one-second target
DB_POLL_SECONDS = 0.5
KEEPALIVE_SECONDS = 15.0
LOG_BACKLOG_LINES = 25
REASONING_BACKLOG = 60
_CONNECT_TIMEOUT = 3

BANNER = "INTERNAL DEMO VIEW - NOT SANITIZED"


def _sse(data: Any, event: Optional[str] = None) -> str:
    head = f"event: {event}\n" if event else ""
    return f"{head}data: {json.dumps(data, default=str)}\n\n"


def _iso(v: Any) -> Any:
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()
    return v


def _row(r: Dict[str, Any]) -> Dict[str, Any]:
    # Phase 6.1: narration + causal link. A row written before migration 005 has no narration; give it a
    # generic line so every entry in the feed reads the same way. caused_by/depth come from the stored row,
    # falling back to the static map for old rows.
    caused_by, depth = r.get("caused_by"), r.get("depth")
    if caused_by is None and not depth:
        caused_by, depth = chain_for(r["agent_name"])
    status = r.get("status") or "resolved"
    if status == "in_progress":
        narration = r.get("narration") or f"{r['agent_name']} is thinking..."
    else:
        narration = r.get("narration") or f"{r['agent_name']} ({r['system'].replace('_', ' ')}) reported."
    return {"event_id": r["event_id"], "incident_id": r["incident_id"], "ts": _iso(r["timestamp"]),
            "system": r["system"], "agent_name": r["agent_name"], "text": r["reasoning_text"],
            "narration": narration, "caused_by": caused_by, "depth": depth or 0,
            "parallel": is_parallel(r["agent_name"]),
            # Phase 6.2: visible in-progress calls (migration 006). status is 'in_progress' | 'resolved' |
            # 'failed'; served_by is the model tag, set only once resolved (best-effort -- see shared.llm).
            "status": status, "served_by": r.get("served_by")}


def _query(sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    with psycopg.connect(store_dsn(), row_factory=dict_row, connect_timeout=_CONNECT_TIMEOUT) as conn:
        return conn.execute(sql, params).fetchall()


def _tail_backlog(path: Path, n: int) -> List[str]:
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            fh.seek(max(0, size - 16384))
            data = fh.read().decode("utf-8", errors="replace")
        lines = [ln for ln in data.splitlines() if ln.strip()]
        return lines[-n:]
    except OSError:
        return []


async def _log_events(request: Request) -> AsyncIterator[str]:
    yield _sse({"banner": BANNER, "file": LOG_FILE.name}, event="hello")
    for line in _tail_backlog(LOG_FILE, LOG_BACKLOG_LINES):
        yield _sse({"line": line, "backlog": True})
    pos: Optional[int] = None
    buf = b""
    idle = 0.0
    while True:
        if await request.is_disconnected():
            return
        try:
            size = LOG_FILE.stat().st_size
        except OSError:
            size = None
        if size is None:                       # file not there yet; keep waiting
            pos = None
        else:
            if pos is None:
                pos = size                     # start at the end (the backlog was already sent)
            elif size < pos:                   # rotated or truncated: start from the top
                pos, buf = 0, b""
            if size > pos:
                def _read(p=pos):
                    with open(LOG_FILE, "rb") as fh:
                        fh.seek(p)
                        return fh.read()
                chunk = await asyncio.to_thread(_read)
                pos += len(chunk)
                buf += chunk
                *complete, buf = buf.split(b"\n")
                for raw in complete:
                    text = raw.decode("utf-8", errors="replace").strip()
                    if text:
                        yield _sse({"line": text, "backlog": False})
                idle = 0.0
        await asyncio.sleep(LOG_POLL_SECONDS)
        idle += LOG_POLL_SECONDS
        if idle >= KEEPALIVE_SECONDS:
            idle = 0.0
            yield ": keepalive\n\n"


async def _reasoning_events(request: Request, incident_id: Optional[str]) -> AsyncIterator[str]:
    yield _sse({"banner": BANNER}, event="hello")
    where, params = ("WHERE incident_id = %s", (incident_id,)) if incident_id else ("", ())
    last = 0
    # Phase 6.2: event_ids this connection has shown as 'in_progress' and is still watching for a
    # resolve/fail transition. `event_id > last` alone would never re-send them -- their id does not
    # change on UPDATE -- so each cycle also re-checks exactly this (small, bounded) set by id.
    in_flight: Dict[int, str] = {}
    try:
        rows = await asyncio.to_thread(
            _query, f'SELECT * FROM (SELECT * FROM reasoning_events {where} ORDER BY event_id DESC LIMIT {REASONING_BACKLOG}) t '
                    "ORDER BY \"timestamp\", event_id", params)
        for r in rows:
            last = max(last, r["event_id"])
            if r.get("status") == "in_progress":
                in_flight[r["event_id"]] = r["status"]
            yield _sse(dict(_row(r), backlog=True))
    except psycopg.Error as exc:
        yield _sse({"error": "incident store unreachable", "detail": type(exc).__name__}, event="problem")
    idle = 0.0
    while True:
        if await request.is_disconnected():
            return
        try:
            rows = await asyncio.to_thread(
                _query, f"SELECT * FROM reasoning_events WHERE event_id > %s {'AND incident_id = %s' if incident_id else ''} "
                        "ORDER BY event_id", (last,) + ((incident_id,) if incident_id else ()))
            for r in rows:
                last = max(last, r["event_id"])
                if r.get("status") == "in_progress":
                    in_flight[r["event_id"]] = r["status"]
                yield _sse(dict(_row(r), backlog=False))
                idle = 0.0
            if in_flight:
                watched = await asyncio.to_thread(
                    _query, "SELECT * FROM reasoning_events WHERE event_id = ANY(%s)", (list(in_flight),))
                for r in watched:
                    if r["status"] != in_flight.get(r["event_id"]):
                        if r["status"] == "in_progress":
                            in_flight[r["event_id"]] = r["status"]
                        else:
                            in_flight.pop(r["event_id"], None)
                        yield _sse(dict(_row(r), backlog=False))
                        idle = 0.0
        except psycopg.Error as exc:
            yield _sse({"error": "incident store unreachable", "detail": type(exc).__name__}, event="problem")
        await asyncio.sleep(DB_POLL_SECONDS)
        idle += DB_POLL_SECONDS
        if idle >= KEEPALIVE_SECONDS:
            idle = 0.0
            yield ": keepalive\n\n"


def build_app() -> FastAPI:
    app = FastAPI(title="Crisis demo - INTERNAL, unsanitized")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    sse_headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"}

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/logs", include_in_schema=False)
    async def logs_page():
        return FileResponse(STATIC_DIR / "logs.html")

    @app.get("/reasoning", include_in_schema=False)
    async def reasoning_page():
        return FileResponse(STATIC_DIR / "reasoning.html")

    @app.get("/health")
    async def health():
        store = "up"
        try:
            _query("SELECT 1")
        except psycopg.Error:
            store = "down"
        return {"status": "ok", "store": store, "log_file": str(LOG_FILE), "log_exists": LOG_FILE.exists(),
                "sanitized": False, "banner": BANNER}

    @app.get("/stream/logs")
    async def stream_logs(request: Request):
        return StreamingResponse(_log_events(request), media_type="text/event-stream", headers=sse_headers)

    @app.get("/logs/backlog")
    async def logs_backlog(n: int = 200):
        """The same backlog /stream/logs sends on connect, as plain JSON (?snapshot=1 on the log tab,
        and screenshotting -- a live SSE connection is awkward for a headless browser to capture)."""
        n = max(1, min(n, 2000))
        lines = await asyncio.to_thread(_tail_backlog, LOG_FILE, n)
        return {"ok": True, "file": LOG_FILE.name, "count": len(lines), "lines": lines}

    @app.get("/stream/reasoning")
    async def stream_reasoning(request: Request, incident_id: Optional[str] = None):
        return StreamingResponse(_reasoning_events(request, incident_id), media_type="text/event-stream",
                                 headers=sse_headers)

    @app.get("/reasoning/events")
    async def reasoning_events(after: int = 0, limit: int = 100, incident_id: Optional[str] = None,
                               in_flight: Optional[str] = None):
        limit = max(1, min(limit, 500))
        # Phase 6.2: `in_flight` lets a polling client (not just the SSE stream) re-fetch specific
        # event_ids it has already shown as in_progress, so it can notice when they resolve/fail --
        # event_id > after alone would never return them again once `after` has moved past them.
        ids = [int(x) for x in in_flight.split(",") if x.strip().lstrip("-").isdigit()] if in_flight else []
        id_clause, id_params = ("OR event_id = ANY(%s)", (ids,)) if ids else ("", ())
        try:
            if incident_id:
                rows = await asyncio.to_thread(
                    _query, f'SELECT * FROM reasoning_events WHERE (event_id > %s {id_clause}) AND incident_id = %s '
                            'ORDER BY "timestamp", event_id LIMIT %s', (after, *id_params, incident_id, limit))
            else:
                rows = await asyncio.to_thread(
                    _query, f'SELECT * FROM reasoning_events WHERE event_id > %s {id_clause} '
                            'ORDER BY "timestamp", event_id LIMIT %s', (after, *id_params, limit))
        except psycopg.Error:
            return JSONResponse(status_code=503, content={"ok": False, "error": "incident store unreachable"})
        return {"ok": True, "sanitized": False, "count": len(rows), "events": [_row(r) for r in rows]}

    @app.get("/incidents/scope")
    async def incidents_scope(limit: int = 20):
        """Phase 6.2 Task 2: what a view can scope to. Reads the same `incidents` table the :8090 trace
        dashboard reads (not a new data source), and derives each incident's IP set from evidence
        Detection already computed -- no new logging, no change to what gets logged, per decision 2.

        Bug found 2026-10-26: `detection/windowing.py`'s aggregate() keeps only the top 5 source IPs
        (`.most_common(5)`), so `ips` below is frequently incomplete for an attack that used more than 5
        -- `attack_simulate.py`'s default brute-force alone spreads across up to 50. A client that used
        `ips` as a hard inclusion filter would silently hide most of a many-IP attack's own traffic. Fixed
        by also reporting `ip_count` (the *true* distinct-IP count Detection saw, from the evidence's own
        tally, not the truncated list) so a view can tell when `ips` is known-incomplete and fall back to
        time-window-only scoping for that incident instead of wrongly excluding real traffic."""
        limit = max(1, min(limit, 100))
        try:
            rows = await asyncio.to_thread(
                _query, "SELECT incident_id, status, created_at, updated_at, severity, raw_payload "
                        "FROM incidents ORDER BY created_at DESC LIMIT %s", (limit,))
        except psycopg.Error:
            return JSONResponse(status_code=503, content={"ok": False, "error": "incident store unreachable"})
        out = []
        for r in rows:
            payload = r.get("raw_payload") or {}
            evidence = ((payload.get("detection") or {}).get("evidence") or {})
            ips = sorted({ip for ip, _ in (evidence.get("top_failed_login_ips") or [])}
                        | {ip for ip, _ in (evidence.get("top_source_ips") or [])})
            ip_count = max(evidence.get("distinct_source_ips") or 0,
                          evidence.get("distinct_ips_with_failed_logins") or 0, len(ips))
            out.append({"incident_id": r["incident_id"], "status": r["status"], "severity": r.get("severity"),
                       "created_at": _iso(r["created_at"]), "updated_at": _iso(r["updated_at"]), "ips": ips,
                       "ip_count": ip_count, "ips_complete": ip_count <= len(ips),
                       "open": r["status"] != "RESOLVED"})
        return {"ok": True, "count": len(out), "incidents": out}

    return app


app = build_app()


def main() -> None:
    load_project_env()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logger.warning("%s -- raw IPs, usernames and full model reasoning are served on :%s", BANNER, DEMO_PORT)
    uvicorn.run(app, host="127.0.0.1", port=DEMO_PORT, log_level="warning")


if __name__ == "__main__":
    main()
