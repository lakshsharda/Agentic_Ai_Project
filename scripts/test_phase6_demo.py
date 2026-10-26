"""Phase 6 proof: branded site, live log tab, live reasoning feed, and the two-pathway separation.

Needs the full stack (scripts/start_all.ps1 or scripts/run_demo.ps1, which now also start the Northwind site
on :8081 and the internal demo backend on :8091).

    .venv-adk\\Scripts\\python scripts/test_phase6_demo.py

  A. The site changes nothing: GET/POST through Northwind return exactly what the app returns, and the
     app's access.log entries for the two routes carry identical fields (only timestamp / request_id /
     duration differ). Pages and assets add NO lines to access.log.
  B. Live log tab: lines reach an SSE client within about a second, measured per line, during a real attack.
  C. Live reasoning feed: one real incident produces reasoning from Detection, Threat Assessment and more,
     in time order, grounded in the incident's real IPs/usernames; the SSE stream delivers a new row quickly.
  D. Separation: the scrubbed trace_events table holds ZERO raw IPs/usernames/hosts after that run, the
     reasoning table does hold them, nothing is copied across, the :8090 dashboard exposes no reasoning, and
     the unsanitized views carry their banner.
  E. A failing reasoning writer degrades to a warning and never blocks or alters a real action.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg
import requests
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shared import reasoning  # noqa: E402
from shared.comms_validation import _INTERNAL_HOST, _IPV4, _IPV6, sensitive_terms  # noqa: E402
from shared.guardrail import check_authority  # noqa: E402
from shared.schemas import IncidentStatus, Severity, new_incident_id  # noqa: E402
from shared.store import IncidentStore, store_dsn  # noqa: E402

PY_APP = ROOT / ".venv-app" / "Scripts" / "python.exe"
SIM = ROOT / "scripts" / "attack_simulate.py"
LOG_FILE = Path(os.environ.get("TARGET_APP_LOG_DIR", ROOT / "target_app" / "logs")) / "access.log"
APP = "http://127.0.0.1:8080"
SITE = "http://127.0.0.1:8081"
DASH = "http://127.0.0.1:8090"
DEMO = "http://127.0.0.1:8091"
ONCALL = "http://127.0.0.1:9104"

store = IncidentStore()
results: Dict[str, bool] = {}


def check(name: str, ok: bool, detail: str = "") -> bool:
    results[name] = bool(ok)
    print(f"[p6] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)
    return bool(ok)


def wait_until(fn, timeout=300, interval=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    return None


def q(sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    with psycopg.connect(store_dsn(), row_factory=dict_row) as conn:
        return conn.execute(sql, params).fetchall()


def log_lines() -> List[str]:
    return [ln for ln in LOG_FILE.read_text(encoding="utf-8").splitlines() if ln.strip()]


# --------------------------------------------------------------------------
# SSE client
# --------------------------------------------------------------------------

class Sse:
    """Background SSE reader that timestamps every data frame on arrival."""

    def __init__(self, url: str):
        self.url, self.items, self._stop = url, [], False
        self.ready = threading.Event()
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        try:
            with requests.get(self.url, stream=True, timeout=(5, 120)) as r:
                self.ready.set()
                for raw in r.iter_lines(decode_unicode=True):
                    if self._stop:
                        return
                    if raw and raw.startswith("data: "):
                        try:
                            self.items.append((time.time(), json.loads(raw[6:])))
                        except ValueError:
                            pass
        except Exception:  # noqa: BLE001
            self.ready.set()

    def stop(self):
        self._stop = True


# --------------------------------------------------------------------------
# A. the site changes nothing
# --------------------------------------------------------------------------

def part_a_site():
    print("\n--- A. the branded site leaves the app's routes and logging unchanged ---")
    for path, name in (("/", "landing"), ("/signin", "sign-in"), ("/account", "account"), ("/static/site.css", "css")):
        r = requests.get(SITE + path, timeout=10)
        check(f"Northwind serves its {name} page", r.status_code == 200 and (len(r.text) > 200), f"{path} {r.status_code}")
    landing = requests.get(SITE + "/", timeout=10).text
    check("the landing page carries a believable identity (name + logo + sign-in)",
          "Northwind Cloud" in landing and "<svg" in landing and "/signin" in landing)

    before = len(log_lines())
    for path in ("/", "/signin", "/account", "/static/site.css"):
        requests.get(SITE + path, timeout=10)
    time.sleep(0.5)
    check("loading pages and assets writes NO lines to access.log (Detection's counts are untouched)",
          len(log_lines()) == before, f"lines before={before} after={len(log_lines())}")

    cases = [("POST", "/login", {"json": {"username": "alice", "password": "wonderland"}}),
             ("POST", "/login", {"json": {"username": "alice", "password": "nope"}}),
             ("POST", "/login", {"json": {"username": "", "password": ""}}),
             ("GET", "/status", {}), ("GET", "/profile", {"params": {"username": "bob"}}),
             ("GET", "/profile", {"params": {"username": "ghost"}}), ("GET", "/profile", {})]
    drop = {"timestamp", "request_id", "duration_ms", "uptime_seconds", "time", "user_agent"}
    same_resp, same_log = True, True
    detail = ""
    for method, path, kw in cases:
        h = {"X-Forwarded-For": "198.51.100.200", "User-Agent": "p6-equivalence"}
        n0 = len(log_lines())
        direct = requests.request(method, APP + path, headers=h, timeout=10, **kw)
        n1 = len(log_lines())
        via = requests.request(method, SITE + path, headers=h, timeout=10, **kw)
        n2 = len(log_lines())
        d_body = {k: v for k, v in direct.json().items() if k not in drop}
        v_body = {k: v for k, v in via.json().items() if k not in drop}
        if direct.status_code != via.status_code or d_body != v_body:
            same_resp, detail = False, f"{method} {path}: {direct.status_code} vs {via.status_code}"
        lines = log_lines()
        e1, e2 = json.loads(lines[n1 - 1]), json.loads(lines[n2 - 1])
        if (n1 - n0 != 1) or (n2 - n1 != 1) or {k: v for k, v in e1.items() if k not in drop} != {
                k: v for k, v in e2.items() if k not in drop}:
            same_log, detail = False, f"{method} {path}: log {e1} vs {e2}"
    check("every route returns the same status code and body through the site as direct", same_resp, detail)
    check("each request writes exactly one access.log entry with identical fields (same source_ip, route, status, outcome)",
          same_log, detail)


# --------------------------------------------------------------------------
# B / C / D. a real attack
# --------------------------------------------------------------------------

def part_bcd_attack() -> Optional[str]:
    print("\n" + "=" * 72 + "\nB/C/D. a real attack through the branded site, all views watching\n" + "=" * 72)
    log_stream = Sse(f"{DEMO}/stream/logs")
    reason_stream = Sse(f"{DEMO}/stream/reasoning")
    log_stream.ready.wait(10)
    reason_stream.ready.wait(10)
    time.sleep(1.5)
    base_log, base_reason = len(log_stream.items), len(reason_stream.items)

    before = (store.list_incidents(limit=1) or [None])[0]
    before = before.incident_id if before else None
    attack_start = time.time()
    subprocess.run([str(PY_APP), str(SIM), "--pattern", "brute-force", "--intensity", "40", "--target-url", SITE,
                    "--delay", "0.05"], check=True, capture_output=True)
    attack_end = time.time()
    iid = wait_until(lambda: (lambda n: n if n and n != before else None)(
        (store.list_incidents(limit=1) or [None])[0].incident_id if store.list_incidents(limit=1) else None), timeout=240)
    if not check("the attack (through the branded site) produced an incident", iid is not None, iid or "none"):
        return None
    print(f"[p6] >>> incident {iid}")

    # ---- B. log tab latency
    time.sleep(2)
    new_items = [(t, d) for t, d in log_stream.items[base_log:] if "line" in d and not d.get("backlog")]
    lags = []
    for recv, d in new_items:
        try:
            ts = datetime.fromisoformat(json.loads(d["line"])["timestamp"]).timestamp()
        except Exception:  # noqa: BLE001
            continue
        lags.append(recv - ts)
    check("the live log tab received the attack's lines", len(lags) >= 30, f"{len(lags)} lines streamed")
    if lags:
        lags.sort()
        p95 = lags[int(len(lags) * 0.95) - 1] if len(lags) > 1 else lags[0]
        check("each line reached the browser stream within about a second of being written",
              p95 <= 1.0 and max(lags) <= 1.5, f"median={lags[len(lags) // 2] * 1000:.0f}ms p95={p95 * 1000:.0f}ms max={max(lags) * 1000:.0f}ms")
    in_log = [d for _, d in new_items if "203.0.113." in d.get("line", "") or "198.51.100." in d.get("line", "")]
    check("the raw lines show real source IPs and usernames (it is the unsanitized tail)",
          bool(in_log) and any('"username"' in d["line"] for d in in_log))

    # ---- drive the incident: human ack so Containment proceeds quickly
    wait_until(lambda: (store.get_incident(iid).raw_payload or {}).get("on_call", {}).get("paged"), timeout=360)
    requests.post(f"{ONCALL}/ack", params={"incident_id": iid, "who": "priya"}, timeout=30)
    wait_until(lambda: store.get_incident(iid).status in ("CONTAINED", "RESOLVED"), timeout=360)

    def have_agents():
        rows = q("SELECT DISTINCT system, agent_name FROM reasoning_events WHERE incident_id = %s", (iid,))
        names = {(r["system"], r["agent_name"]) for r in rows}
        systems = {s for s, _ in names}
        return names if {"detection", "threat_assessment", "containment"} <= systems else None
    names = wait_until(have_agents, timeout=120, interval=3) or set()
    # give Forensics / Comms a chance (they follow later and are model-dependent); not required
    wait_until(lambda: {"forensics", "customer_comms"} & {s for s, _ in (have_agents() or set())}, timeout=150, interval=5)
    time.sleep(3)
    reasoning.flush(5)

    # ---- C. reasoning feed
    rows = q('SELECT * FROM reasoning_events WHERE incident_id = %s ORDER BY "timestamp", event_id', (iid,))
    systems = [r["system"] for r in rows]
    check("reasoning rows exist for Detection, Threat Assessment and Containment",
          {"detection", "threat_assessment", "containment"} <= set(systems), f"systems={sorted(set(systems))}")
    extra = {"forensics", "customer_comms", "on_call"} & set(systems)
    print(f"[p6]     also present: {sorted(extra) or 'none yet'}   agents: {sorted({r['agent_name'] for r in rows})}")
    first = {s: next(r["timestamp"] for r in rows if r["system"] == s) for s in set(systems)}
    check("reasoning is time-ordered across systems: Detection, then Threat Assessment, then Containment",
          first["detection"] < first["threat_assessment"] < first["containment"],
          " < ".join(f"{s}@{first[s].strftime('%H:%M:%S.%f')[:-3]}" for s in ("detection", "threat_assessment", "containment")))
    check("rows are returned in non-decreasing time order",
          [r["timestamp"] for r in rows] == sorted(r["timestamp"] for r in rows))
    rec = store.get_incident(iid)
    ev = ((rec.raw_payload or {}).get("detection") or {}).get("evidence", {})
    ips = [ip for ip, _ in (ev.get("top_failed_login_ips") or [])]
    users = [u for u, _ in (ev.get("top_targeted_usernames") or [])]
    blob = "\n".join(r["reasoning_text"] for r in rows)
    check("the reasoning is grounded in this incident's real data (real attacker IPs and usernames appear in the text)",
          any(ip in blob for ip in ips) and any(u in blob for u in users), f"ips={ips[:3]} users={users[:3]}")
    check("every entry has non-trivial text and a named agent",
          all(len(r["reasoning_text"].strip()) > 20 and r["agent_name"] for r in rows),
          f"shortest={min(len(r['reasoning_text']) for r in rows)} chars")
    api = requests.get(f"{DEMO}/reasoning/events", params={"incident_id": iid, "limit": 200}, timeout=15).json()
    check("/reasoning/events returns the same rows the table holds",
          [e["event_id"] for e in api["events"]] == [r["event_id"] for r in rows] and api["sanitized"] is False)
    streamed = [d for _, d in reason_stream.items[base_reason:] if d.get("incident_id") == iid]
    check("the live reasoning stream delivered this incident's entries as they were written",
          {"detection", "threat_assessment"} <= {d["system"] for d in streamed}, f"{len(streamed)} entries streamed")
    for _, d in log_stream.items[:0]:
        pass
    log_stream.stop()
    reason_stream.stop()
    return iid


def part_stream_latency():
    print("\n--- C2. a new reasoning row reaches the live stream quickly ---")
    s = Sse(f"{DEMO}/stream/reasoning")
    s.ready.wait(10)
    time.sleep(1.5)
    marker = f"p6-latency-{new_incident_id()[-6:]}"
    t0 = time.time()
    reasoning.record_reasoning(system="detection", agent_name="p6 latency probe", text="probe " + marker, incident_id=marker)
    got = wait_until(lambda: [t for t, d in s.items if d.get("incident_id") == marker], timeout=10, interval=0.1)
    lag = (got[0] - t0) if got else None
    check("a freshly written reasoning row appears on the stream within about a second",
          lag is not None and lag <= 2.0, f"{lag * 1000:.0f}ms" if lag is not None else "never arrived")
    s.stop()
    reasoning.flush(5)
    q("DELETE FROM reasoning_events WHERE incident_id = %s RETURNING 1", (marker,))


def part_d_separation(iid: str):
    print("\n--- D. the scrubbed audit trail and the unsanitized feed stay separate ---")
    rec = store.get_incident(iid)
    terms = sensitive_terms(rec.raw_payload or {})
    users = {u for u in terms["usernames"] if len(u) > 2}
    ev = ((rec.raw_payload or {}).get("detection") or {}).get("evidence", {})
    ips = [ip for ip, _ in (ev.get("top_failed_login_ips") or [])]

    trace_rows = q("SELECT incident_id, summary, detail FROM trace_events")
    tt = [json.dumps([r["summary"], r["detail"]]) for r in trace_rows]
    check(f"trace_events (all {len(trace_rows)} rows, including this run) holds zero raw IPs",
          not [t for t in tt if _IPV4.search(t) or _IPV6.search(t)])
    check("trace_events holds zero internal hostnames", not [t for t in tt if _INTERNAL_HOST.search(t)])
    pat = re.compile(r"\b(?:" + "|".join(re.escape(u) for u in sorted(users)) + r")\b", re.IGNORECASE) if users else None
    mine = [t for r, t in zip(trace_rows, tt) if r["incident_id"] == iid]
    check("trace_events holds none of this incident's targeted usernames",
          not (pat and [t for t in mine if pat.search(t)]), f"usernames checked={sorted(users)}; trace rows for it={len(mine)}")
    rtext = "\n".join(r["reasoning_text"] for r in q("SELECT reasoning_text FROM reasoning_events WHERE incident_id = %s", (iid,)))
    check("while reasoning_events genuinely contains them (two different pathways, not one filtered view)",
          any(ip in rtext for ip in ips) and bool(pat and pat.search(rtext)))
    trace_summaries = {r["summary"] for r in trace_rows}
    reasoning_texts = [r["reasoning_text"] for r in q("SELECT reasoning_text FROM reasoning_events WHERE incident_id = %s", (iid,))]
    check("no reasoning text was copied into trace_events", not [t for t in reasoning_texts if t in trace_summaries])
    cols = {r["column_name"] for r in q("SELECT column_name FROM information_schema.columns WHERE table_name = 'trace_events'")}
    check("the scrubbed table gained no new unsanitized columns", cols == {"event_id", "incident_id", "timestamp", "from_system",
                                                                          "to_system", "event_type", "decision", "summary", "detail"}, str(sorted(cols)))
    # the audit dashboard must not serve reasoning at all
    r1 = requests.get(f"{DASH}/reasoning", timeout=10)
    r2 = requests.get(f"{DASH}/reasoning/events", timeout=10)
    api_all = json.dumps(requests.get(f"{DASH}/incidents/{iid}/timeline", timeout=15).json())
    check("the :8090 audit dashboard exposes no reasoning route and returns no raw IPs for this incident",
          r1.status_code == 404 and r2.status_code == 404 and not (_IPV4.search(api_all) or _IPV6.search(api_all)))
    for path in ("/logs", "/reasoning"):
        page = requests.get(DEMO + path, timeout=10).text
        check(f"the {path} tab is explicitly marked as the unsanitized internal view",
              "INTERNAL DEMO VIEW" in page and "NOT SANITIZED" in page)
    check("the :8091 health endpoint declares itself unsanitized", requests.get(f"{DEMO}/health", timeout=10).json().get("sanitized") is False)


# --------------------------------------------------------------------------
# E. degrade to a warning
# --------------------------------------------------------------------------

class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.records: List[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


def part_e_degrade():
    print("\n--- E. a failing reasoning writer must never block or alter a real action ---")
    cap = _Capture()
    rlog = logging.getLogger("shared.reasoning")
    rlog.addHandler(cap)
    old = rlog.level
    rlog.setLevel(logging.WARNING)
    reasoning._last_warn = 0.0
    marker = f"p6-degrade-{new_incident_id()[-6:]}"
    os.environ["REASONING_STORE_DSN"] = "postgresql://crisis:wrong@127.0.0.1:1/none?connect_timeout=1"
    iid = new_incident_id()
    store.create_incident(iid, status=IncidentStatus.DETECTED, severity=Severity.HIGH, incident_type="x")
    try:
        t0 = time.perf_counter()
        reasoning.record_reasoning(system="detection", agent_name="probe", text="written while the store is down", incident_id=marker)
        dt = time.perf_counter() - t0
        check("record_reasoning returns immediately with an unreachable store", dt < 0.2, f"{dt * 1000:.1f} ms")
        ok_a = check_authority("containment", "customer_comms", "notify_status", incident_id=iid)
        ok_b = check_authority("on_call", "customer_comms", "notify_status", incident_id=iid)
        rec = store.advance_status(iid, IncidentStatus.CANDIDATE, by_system="threat_assessment")
        check("real decisions are unaffected (authority answers right, status still advances)",
              ok_a is True and ok_b is False and rec.status == "CANDIDATE")
        for weird in ({"text": None}, {"text": object()}, {"text": ""}):
            reasoning.record_reasoning(system="detection", agent_name="probe", incident_id=marker, **weird)
        check("malformed arguments are swallowed, not raised", True)
        reasoning.flush(15)
        warned = [r for r in cap.records if "reasoning write failed" in r.getMessage()]
        check("the failure degrades to a logged warning and the writer drains", bool(warned) and reasoning.pending() == 0,
              warned[0].getMessage()[:100] if warned else "no warning")
        check("nothing was written while the writer was broken",
              not q("SELECT 1 FROM reasoning_events WHERE incident_id = %s", (marker,)))
    finally:
        os.environ.pop("REASONING_STORE_DSN", None)
        rlog.removeHandler(cap)
        rlog.setLevel(old)
        store.delete_incident(iid)
    time.sleep(reasoning._COOLDOWN_SECONDS + 1)
    reasoning.record_reasoning(system="detection", agent_name="probe", text="written after recovery", incident_id=marker)
    reasoning.flush(10)
    check("the writer recovers once the store is back", bool(q("SELECT 1 FROM reasoning_events WHERE incident_id = %s", (marker,))))
    q("DELETE FROM reasoning_events WHERE incident_id = %s RETURNING 1", (marker,))


def main() -> int:
    for name, url in (("target app", f"{APP}/status"), ("northwind site", f"{SITE}/"), ("trace dashboard", f"{DASH}/health"),
                      ("internal demo", f"{DEMO}/health")):
        try:
            requests.get(url, timeout=5).raise_for_status()
        except Exception as exc:  # noqa: BLE001
            print(f"[p6] {name} not reachable ({exc}); start the stack first (scripts/start_all.ps1)")
            return 1
    part_a_site()
    iid = part_bcd_attack()
    part_stream_latency()
    if iid:
        part_d_separation(iid)
    part_e_degrade()

    failed = [k for k, v in results.items() if not v]
    print(f"\n[p6] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[p6] FAILED: " + ", ".join(failed))
        return 1
    print("[p6] ALL PASSED -- site unchanged, live log, live reasoning, two separate pathways, degrade-to-warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
