"""Phase 6.1 checks: the narration layer on the reasoning feed, and the login -> dashboard path.

    .venv-adk\\Scripts\\python scripts/test_phase61_narration.py

Needs the stack up (scripts\\run_demo.ps1 -NoAttack -Headless). It writes only clearly-marked probe rows and
removes them. It does NOT start an attack; it reads the newest real incident for the end-to-end checks.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import psycopg
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared import reasoning  # noqa: E402
from shared.narration import CHAIN, chain_for, is_parallel  # noqa: E402

DEMO = "http://127.0.0.1:8091"
SITE = "http://127.0.0.1:8081"
DASH = "http://127.0.0.1:8090"
LOG = Path(__file__).resolve().parents[1] / "target_app" / "logs" / "access.log"
MARK = "p61-probe-" + str(int(time.time()))
ok_all = True


def check(name: str, cond: bool, detail: str = "") -> None:
    global ok_all
    ok_all &= bool(cond)
    print(f"[p61] {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def main() -> int:
    print("--- A. causal map ---")
    check("the root has no parent and depth 0", chain_for("Noise Filtering Agent") == (None, 0))
    check("every mapped parent is itself in the map (no dangling arrows)",
          all(p is None or p in CHAIN for p, _ in CHAIN.values()))
    check("depth is parent depth + 1 everywhere",
          all(p is None or d == CHAIN[p][1] + 1 for p, d in CHAIN.values()))
    check("the three dispatch targets are flagged parallel",
          all(is_parallel(a) for a in ("Containment Planning Agent", "On-Call Paging Agent", "Root Cause Analysis Agent")))
    check("sequential steps are not flagged parallel", not is_parallel("Recovery Planning Agent"))
    check("an unmapped agent is a depth-0 root", chain_for("Some New Agent") == (None, 0))

    print("\n--- B. narration is stored and served ---")
    reasoning.record_reasoning(system="detection", agent_name="Correlation Agent", incident_id=MARK, text="raw text A",
                               narration="  a   story\nline  ")
    reasoning.record_reasoning(system="forensics", agent_name="Recovery Planning Agent", incident_id=MARK, text="raw text B")
    check("writer flushed", reasoning.flush(8.0))
    try:
        rows = requests.get(f"{DEMO}/reasoning/events", params={"incident_id": MARK}, timeout=10).json()["events"]
        check("both probe rows came back", len(rows) == 2, str(len(rows)))
        a = next(r for r in rows if r["text"] == "raw text A")
        b = next(r for r in rows if r["text"] == "raw text B")
        check("whitespace in the narration is normalised to one line", a["narration"] == "a story line", a["narration"])
        check("the raw text is untouched alongside the narration", a["text"] == "raw text A")
        check("caused_by/depth come from the causal map", (a["caused_by"], a["depth"]) == ("Noise Filtering Agent", 1))
        check("an entry without a narration still gets a plain-English line", bool(b["narration"]) and "reported" in b["narration"], b["narration"])
    finally:
        with psycopg.connect(reasoning.reasoning_dsn(), autocommit=True) as c:
            c.execute("DELETE FROM reasoning_events WHERE incident_id = %s", (MARK,))

    print("\n--- C. every entry of the newest real incident is narrated and traceable ---")
    iid = requests.get(f"{DASH}/incidents", params={"limit": 1}, timeout=10).json()["incidents"][0]["incident_id"]
    rows = requests.get(f"{DEMO}/reasoning/events", params={"incident_id": iid, "limit": 200}, timeout=10).json()["events"]
    check(f"{iid}: the incident has reasoning entries", len(rows) > 0, str(len(rows)))
    check("every entry has a non-empty narration", all(r["narration"].strip() for r in rows))
    check("no narration is just the generic fallback (callers supplied real ones)",
          not any(" reported." in r["narration"] for r in rows), "; ".join(r["agent_name"] for r in rows if " reported." in r["narration"]))
    names = {r["agent_name"] for r in rows}
    check("every non-root entry's parent is present in the same incident, earlier in time",
          all(r["caused_by"] is None or any(p["agent_name"] == r["caused_by"] and p["ts"] <= r["ts"] for p in rows) for r in rows),
          f"agents={sorted(names)}")

    print("\n--- D. the branded login -> dashboard path, and the log contract ---")
    before = sum(1 for _ in open(LOG, encoding="utf-8")) if LOG.exists() else 0
    r = requests.post(f"{SITE}/login", json={"username": "alice", "password": "wonderland"}, timeout=10)
    check("alice/wonderland logs in through the site", r.status_code == 200 and r.json().get("success") is True)
    bad = requests.post(f"{SITE}/login", json={"username": "alice", "password": "nope"}, timeout=10)
    check("a wrong password is an ordinary 401 with the normal error", bad.status_code == 401 and "invalid" in bad.json().get("error", ""))
    page = requests.get(f"{SITE}/account", timeout=10)
    check("the account dashboard page is served", page.status_code == 200 and "Recent sign-ins" in page.text and "Compute hours" in page.text)
    check("the sign-in page tells the presenter the demo account", "wonderland" in requests.get(f"{SITE}/signin", timeout=10).text)
    requests.get(f"{SITE}/profile", params={"username": "alice"}, timeout=10)
    requests.get(f"{SITE}/status", timeout=10)
    time.sleep(0.3)
    new = [json.loads(ln) for ln in open(LOG, encoding="utf-8").read().splitlines()[before:] if ln.strip()]
    check("exactly the 4 API calls wrote log lines (serving the pages wrote none)", len(new) == 4, f"{len(new)} new lines")
    want = {"timestamp", "request_id", "source_ip", "method", "endpoint", "status_code", "success", "auth_outcome",
            "username", "user_agent", "duration_ms"}
    check("every new line has exactly the original access.log fields", all(set(e) == want for e in new))

    print(f"\n[p61] {'ALL PASSED' if ok_all else 'FAILURES'}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
