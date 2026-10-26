"""Phase 0 check for the target app and its access log.

Hits every endpoint, then re-reads the log file and asserts that each request
produced exactly one well-formed entry with the fields Phase 1's Detection
system will depend on.

    .venv-app\\Scripts\\python target_app/app.py          # in one terminal
    .venv-app\\Scripts\\python scripts/test_target_app.py  # in another

Point it elsewhere once the app is deployed or containerised:

    TARGET_APP_URL=https://... python scripts/test_target_app.py

Setting TARGET_APP_URL turns the log-file assertions off, because a remote or
containerised app writes its log somewhere this script cannot read -- check
its stdout (`docker logs`, or the platform's log sink) instead. Force the
assertions back on with TARGET_APP_CHECK_LOG=1.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

import requests

BASE_URL = os.environ.get("TARGET_APP_URL", "http://127.0.0.1:8080").rstrip("/")
LOG_FILE = Path(
    os.environ.get("TARGET_APP_LOG_DIR", Path(__file__).resolve().parents[1] / "target_app" / "logs")
) / "access.log"

# Every entry must carry these. Phase 1 reads them by name.
REQUIRED_FIELDS = [
    "timestamp",
    "request_id",
    "source_ip",
    "method",
    "endpoint",
    "status_code",
    "success",
    "auth_outcome",
    "username",
    "user_agent",
    "duration_ms",
]

results: Dict[str, bool] = {}


def check(name: str, ok: bool, detail: str = "") -> None:
    results[name] = ok
    print(f"[app] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def read_log() -> List[Dict[str, Any]]:
    if not LOG_FILE.exists():
        return []
    entries = []
    with LOG_FILE.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def main() -> int:
    print(f"[app] target  = {BASE_URL}")
    print(f"[app] logfile = {LOG_FILE}\n")

    log_before = len(read_log())

    # The log file is only readable from here when the app is a host process
    # writing to this repo. A container or a deployed instance writes its log
    # inside its own filesystem, so asserting on the local file would fail for
    # reasons that have nothing to do with the app.
    check_log = os.environ.get(
        "TARGET_APP_CHECK_LOG", "0" if os.environ.get("TARGET_APP_URL") else "1"
    ) == "1"

    cases = [
        ("GET  /status", lambda: requests.get(f"{BASE_URL}/status", timeout=10), 200),
        (
            "POST /login  valid",
            lambda: requests.post(
                f"{BASE_URL}/login",
                json={"username": "alice", "password": "wonderland"},
                timeout=10,
            ),
            200,
        ),
        (
            "POST /login  wrong password",
            lambda: requests.post(
                f"{BASE_URL}/login",
                json={"username": "alice", "password": "wrong"},
                timeout=10,
            ),
            401,
        ),
        (
            "POST /login  missing fields",
            lambda: requests.post(f"{BASE_URL}/login", json={"username": "alice"}, timeout=10),
            400,
        ),
        (
            "GET  /profile known user",
            lambda: requests.get(f"{BASE_URL}/profile", params={"username": "admin"}, timeout=10),
            200,
        ),
        (
            "GET  /profile unknown user",
            lambda: requests.get(f"{BASE_URL}/profile", params={"username": "nobody"}, timeout=10),
            404,
        ),
        ("GET  /nope (404)", lambda: requests.get(f"{BASE_URL}/nope", timeout=10), 404),
    ]

    for label, call, expected in cases:
        try:
            resp = call()
        except Exception as exc:  # noqa: BLE001
            check(label, False, str(exc))
            continue
        check(label, resp.status_code == expected, f"got {resp.status_code}, want {expected}")

    # The login outcome must be distinguishable, not just the HTTP status --
    # Detection keys off auth_outcome.
    good = requests.post(
        f"{BASE_URL}/login", json={"username": "bob", "password": "builder123"}, timeout=10
    ).json()
    bad = requests.post(
        f"{BASE_URL}/login", json={"username": "bob", "password": "nope"}, timeout=10
    ).json()
    check("valid login reports success=true", good.get("success") is True)
    check("invalid login reports success=false", bad.get("success") is False)

    if not check_log:
        print(
            "\n[app] NOTE  TARGET_APP_URL is set -- skipping local log-file assertions."
            "\n[app] NOTE  Verify the access log on the target itself (e.g. `docker logs`)."
        )
    else:
        time.sleep(0.3)  # let the file handler flush
        entries = read_log()
        new = entries[log_before:]
        check("requests produced new log entries", len(new) >= len(cases), f"{len(new)} new lines")

        if new:
            missing = {f for e in new for f in REQUIRED_FIELDS if f not in e}
            check(
                "every entry has all required fields",
                not missing,
                f"missing: {sorted(missing)}" if missing else ", ".join(REQUIRED_FIELDS),
            )

            failed_login = [
                e for e in new if e["endpoint"] == "/login" and e["auth_outcome"] == "invalid_credentials"
            ]
            check(
                "failed logins are logged with auth_outcome=invalid_credentials",
                bool(failed_login),
                f"{len(failed_login)} found",
            )
            check(
                "failed logins carry success=false and status 401",
                all(e["success"] is False and e["status_code"] == 401 for e in failed_login),
            )
            check(
                "failed logins carry the attempted username",
                all(e["username"] for e in failed_login),
            )
            check(
                "every entry carries a source_ip",
                all(e.get("source_ip") for e in new),
                new[0].get("source_ip", ""),
            )
            check(
                "request_ids are unique",
                len({e["request_id"] for e in new}) == len(new),
            )

            print("\n[app] sample entry:")
            print("      " + json.dumps(failed_login[0] if failed_login else new[0]))

    failed = [k for k, v in results.items() if not v]
    print(f"\n[app] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[app] FAILED: " + ", ".join(failed))
        return 1
    print("[app] ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
