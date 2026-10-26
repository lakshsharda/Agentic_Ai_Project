"""Traffic generator for the local target app.

Produces the access-log entries Detection reads. It is the trigger/test
mechanism for this phase and every later one, so it is configurable rather
than hardcoded to one scenario.

Patterns:
  * brute-force  -- many POST /login with wrong passwords in a short window,
                    across several usernames and (simulated) source IPs
  * burst        -- a spike of GET /status or /profile requests
  * baseline     -- quiet, mostly-legitimate traffic; the "nothing is wrong"
                    control case Detection must NOT escalate

Examples:
    python scripts/attack_simulate.py --pattern brute-force --intensity 40
    python scripts/attack_simulate.py --pattern baseline
    python scripts/attack_simulate.py --pattern burst --endpoint /status --intensity 60
    python scripts/attack_simulate.py --pattern brute-force --target-url http://127.0.0.1:8080
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional

import requests

DEFAULT_TARGET = "http://127.0.0.1:8080"

# Usernames an attacker would guess. "admin"/"root" are the obvious ones; the
# valid demo users (alice, bob) are included so some attempts look like a real
# user mistyping, which is exactly the ambiguity Detection has to reason about.
GUESS_USERNAMES = ["admin", "root", "administrator", "test", "oracle", "alice", "bob", "guest"]
WRONG_PASSWORDS = ["123456", "password", "admin", "letmein", "qwerty", "root", "changeme"]

# Simulated attacker source IPs. The app reads X-Forwarded-For first, so these
# land in the log's source_ip field -- letting one run look like a botnet
# (many IPs) or a single host hammering (one IP).
BOTNET_IPS = [f"203.0.113.{n}" for n in range(10, 60)]       # TEST-NET-3
SINGLE_ATTACKER_IP = "198.51.100.77"                         # TEST-NET-2
LEGIT_IPS = ["192.0.2.15", "192.0.2.16", "192.0.2.17"]       # TEST-NET-1


@dataclass
class RunStats:
    sent: int = 0
    by_status: dict = field(default_factory=dict)
    errors: int = 0

    def record(self, status_code: Optional[int]) -> None:
        self.sent += 1
        if status_code is None:
            self.errors += 1
        else:
            self.by_status[status_code] = self.by_status.get(status_code, 0) + 1


def _post_login(
    session: requests.Session,
    base: str,
    username: str,
    password: str,
    source_ip: str,
    timeout: float,
) -> Optional[int]:
    try:
        resp = session.post(
            f"{base}/login",
            json={"username": username, "password": password},
            headers={"X-Forwarded-For": source_ip, "User-Agent": "sim-attack/1.0"},
            timeout=timeout,
        )
        return resp.status_code
    except requests.RequestException as exc:
        print(f"  ! request failed: {exc}", file=sys.stderr)
        return None


def _get(
    session: requests.Session,
    base: str,
    path: str,
    source_ip: str,
    timeout: float,
) -> Optional[int]:
    try:
        resp = session.get(
            f"{base}{path}",
            headers={"X-Forwarded-For": source_ip, "User-Agent": "sim-attack/1.0"},
            timeout=timeout,
        )
        return resp.status_code
    except requests.RequestException as exc:
        print(f"  ! request failed: {exc}", file=sys.stderr)
        return None


# Valid demo credentials, so the simulator can model a *successful* compromise
# (some stuffed credentials actually work) -- the signal Forensics escalates on.
VALID_CREDS = {"alice": "wonderland", "bob": "builder123"}


def run_brute_force(session, base, intensity, delay, timeout, single_source, successes=0) -> RunStats:
    """Repeated failed logins -- the signal Detection should escalate.

    `successes` > 0 mixes in that many *successful* logins from attacker IPs,
    modelling a credential-stuffing attack that partially worked. Those land in
    the access log as auth_outcome=success, so the incident's evidence carries
    `successful_logins` -- which Forensics treats as confirmed compromise.
    """
    stats = RunStats()
    print(
        f"[sim] brute-force: {intensity} failed logins + {successes} successful, "
        f"source={'one host' if single_source else 'many IPs'}"
    )
    for _ in range(intensity):
        ip = SINGLE_ATTACKER_IP if single_source else random.choice(BOTNET_IPS)
        username = random.choice(GUESS_USERNAMES)
        password = random.choice(WRONG_PASSWORDS)
        stats.record(_post_login(session, base, username, password, ip, timeout))
        time.sleep(delay)
    for _ in range(successes):
        ip = SINGLE_ATTACKER_IP if single_source else random.choice(BOTNET_IPS)
        user, pw = random.choice(list(VALID_CREDS.items()))
        stats.record(_post_login(session, base, user, pw, ip, timeout))
        time.sleep(delay)
    return stats


def run_burst(session, base, endpoint, intensity, delay, timeout) -> RunStats:
    """A spike of GETs against one endpoint."""
    stats = RunStats()
    print(f"[sim] burst: {intensity} GET {endpoint}")
    for _ in range(intensity):
        ip = random.choice(BOTNET_IPS)
        path = endpoint
        if endpoint == "/profile":
            path = f"/profile?username={random.choice(GUESS_USERNAMES)}"
        stats.record(_get(session, base, path, ip, timeout))
        time.sleep(delay)
    return stats


def run_baseline(session, base, intensity, delay, timeout) -> RunStats:
    """Quiet, mostly-legitimate traffic -- the control Detection must NOT escalate.

    A couple of valid logins, some status checks, the occasional single typo.
    Nothing here should look like an attack.
    """
    stats = RunStats()
    n = max(4, intensity // 4)
    print(f"[sim] baseline: ~{n} mixed, mostly-legitimate requests")
    valid = {"alice": "wonderland", "bob": "builder123"}
    for i in range(n):
        ip = random.choice(LEGIT_IPS)
        roll = random.random()
        if roll < 0.5:
            stats.record(_get(session, base, "/status", ip, timeout))
        elif roll < 0.85:
            user = random.choice(list(valid))
            stats.record(_post_login(session, base, user, valid[user], ip, timeout))
        else:
            # one honest mistake -- a real user mistyping once
            stats.record(_post_login(session, base, "alice", "wrongonce", ip, timeout))
        time.sleep(delay)
    return stats


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate traffic against the target app.")
    parser.add_argument("--target-url", default=DEFAULT_TARGET)
    parser.add_argument(
        "--pattern",
        choices=["brute-force", "burst", "baseline"],
        default="brute-force",
    )
    parser.add_argument(
        "--intensity", type=int, default=40, help="roughly how many requests to send"
    )
    parser.add_argument(
        "--delay", type=float, default=0.05, help="seconds between requests"
    )
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--endpoint", default="/status", choices=["/status", "/profile"],
        help="burst target endpoint",
    )
    parser.add_argument(
        "--single-source", action="store_true",
        help="brute-force from one IP instead of many",
    )
    parser.add_argument(
        "--successes", type=int, default=0,
        help="brute-force: mix in N successful logins (models a partial compromise)",
    )
    args = parser.parse_args(argv)

    base = args.target_url.rstrip("/")

    # Fail fast if the app is not up, rather than logging a wall of errors.
    try:
        requests.get(f"{base}/status", timeout=5).raise_for_status()
    except requests.RequestException as exc:
        print(f"[sim] target app not reachable at {base}: {exc}", file=sys.stderr)
        print("[sim] start it first:  .venv-app\\Scripts\\python target_app\\app.py", file=sys.stderr)
        return 1

    print(f"[sim] target = {base}")
    started = time.time()

    with requests.Session() as session:
        if args.pattern == "brute-force":
            stats = run_brute_force(
                session, base, args.intensity, args.delay, args.timeout, args.single_source,
                successes=args.successes,
            )
        elif args.pattern == "burst":
            stats = run_burst(
                session, base, args.endpoint, args.intensity, args.delay, args.timeout
            )
        else:
            stats = run_baseline(session, base, args.intensity, args.delay, args.timeout)

    elapsed = time.time() - started
    print(
        f"[sim] done: {stats.sent} requests in {elapsed:.1f}s, "
        f"status breakdown={stats.by_status}, transport errors={stats.errors}"
    )
    print("[sim] check target_app/logs/access.log for the entries just produced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
