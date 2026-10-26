# Phase 6.3 — 20-Case Live Validation Matrix

All 20 cases below are run live, for real, against the actual LLM chain and the actual guardrail/gate
code — no mocking. Cases 1 and 2 were launched by the user in this same live session, moments before this
table was finalized (a hybrid credential-stuffing attack and an injection-probe attack, both already run
to completion); rather than spend real LLM calls re-producing equivalent runs, their real outcomes are
used directly as this matrix's evidence for cases 1-2. Every other case is launched fresh after this table
is written.

**Time / spend estimate (Decision 6):** ~10-11 of the 20 cases need a fresh live attack through part or
all of the six-system chain; each spends roughly 8-11 real model calls (Detection x1, Threat Assessment
x2-3, Containment x1, On-Call x1, Forensics x2, Customer Comms x1-3) and takes 1-5 minutes wall-clock
(the Phase 6.1 dry run saw 20s-4.5min per dispatch, highly variable). The other ~9 cases are fast,
real-but-non-LLM scripted actions (an authority-matrix denial, a publish-gate refusal, a validator
rejection, API scoping checks) taking seconds each. **Estimate: roughly 100-150 real LLM calls total
across the matrix, 45-90 minutes of wall-clock**, run with several attacks in flight concurrently rather
than fully serial waits. Proceeding straight into execution per Decision 6.

| # | Case | Tests | Pattern / action | Expected outcome |
|---|---|---|---|---|
| 1 | Hybrid credential-stuffing, confirmed compromise | Full chain, High/Critical severity, human-approved gate, recovery lift | `attack_live.py --auto-ack` (default) | Escalates, human-approved gate, `safe_to_lift=True`, RESOLVED |
| 2 | Injection/fuzzing probe | A different attack TYPE still tripping the same signal; recovery refusal | `attack_live.py --pattern injection-probe --auto-ack` | Escalates (same signal as brute force), `safe_to_lift=False`, stays CONTAINED |
| 3 | Authority-matrix denial | A forged A2A message from a system not authorized for that action pair is denied | Direct HTTP POST to Containment's A2A endpoint, `source_system=customer_comms`, `action=request_action` | `check_authority` denies it for real; traced as `authority denied` |
| 4 | Publish gate refuses a `timeout_escalation` "approver" | The publish gate never accepts a system value as sign-off | `comms_signoff.py approve <pending draft> --as timeout_escalation` | Refused — not a human identity |
| 5 | Comms draft validator rejection | A human edit containing a raw IP is rejected by the real validator, not silently published | `comms_signoff.py approve <pending draft> --as <human> --edit "<text with an IP>"` | Rejected with the IP-leak reason; not published |
| 6 | Enumeration-only, no escalation (known gap) | Confirms the documented Phase 7 gap still reproduces | `attack_live.py --stage enum` | No incident opens |
| 7 | Baseline negative control | Normal traffic does not cry wolf | `attack_live.py --pattern baseline` | No incident opens |
| 8 | Low-intensity, single-source brute force | Severity floor — does a small, quiet attack rate Low (or not escalate at all)? | `attack_simulate.py --pattern brute-force --intensity 8 --single-source` | Reported as observed, not forced |
| 9 | Medium-volume, multi-IP brute force, no successes | Mid-range severity, likely auto-pass gate (no approval required) | `attack_simulate.py --pattern brute-force --intensity 18` | Reported as observed; watch for `no approval required` gate line |
| 10 | Slow-hybrid, jittery pacing | Detection still catches a less obviously bursty pattern | `attack_live.py --pattern slow-hybrid --auto-ack` | Expected to escalate (unconfirmed before this phase) |
| 11 | Pure credential-stuffing burst, no recon | A third distinct shape against known-real accounts | `attack_live.py --pattern burst --auto-ack` | Escalates |
| 12 | Containment gate opened by **timeout escalation**, not a human | The 4th gate-decision type: no ack given, the escalation window lapses | `attack_live.py` (no `--auto-ack`), deliberately do not ack | Gate stays `PENDING_APPROVAL`/`PENDING_EVIDENCE` (case 13), then opens via `timeout_escalation`, not `human` |
| 13 | Gate held/blocked before resolution | Captured as the intermediate state inside case 12, before its timeout fires | (same run as 12, read mid-flight) | `state: PENDING_EVIDENCE` or `PENDING_APPROVAL`, `executed: false` |
| 14 | High-successes hybrid attack, aiming Critical + reclassification | Top severity band; Forensics' feedback loop suggesting a reclassification | `attack_live.py --auto-ack` with `attack_simulate.py`-style `--successes 4` traffic | Reported as observed — severity and whether reclassify fires are model judgment, not guaranteed |
| 15 | Concurrent incidents, per-incident scoping | Two real, simultaneously-open incidents are correctly isolated in both live views | API check: `/incidents/scope` + `/reasoning/events?incident_id=` for cases 1 and 2 while both were open | Each incident's events/IPs never leak into the other's filtered view |
| 16 | Cross-provider LLM fallback, observed | Did any case's model calls fail over to a non-primary provider? | Log scan across all cases for `RateLimitError` / `Fallback attempt` / non-primary `served_by` | Reported as observed (already seen earlier this session) |
| 17 | Second hybrid run, clean timing sample | A second data point for dispatch timing under current (post-rate-limit) conditions | `attack_live.py --auto-ack` (default), fresh run | Reported as observed |
| 18 | Single honest mistake (one wrong password, nothing else) | The extreme quiet end of the non-escalation boundary | One direct `POST /login` with a wrong password, no other traffic | No incident opens |
| 19 | Human-edited draft that still validates, published | The publish gate's happy path with a human edit, distinct from cases 4/5's refusals | `comms_signoff.py approve <a later pending draft> --as <human> --edit "<clean text>"` | `edited_by_human=true`, published |
| 20 | Second concurrency + fallback stress | Two more attacks launched overlapping, both to reinforce case 15's scoping proof and add fallback pressure | Two of the above patterns launched back-to-back | Both incidents open at once; scoping still isolates them |

Evidence for each case is recorded below as it is produced.

---

## Results

### Case 1 — Hybrid credential-stuffing, confirmed compromise
**Incident:** `inc-c1fa636934ad`. **Outcome:** escalated, severity **High**, gate **human-approved**
(`approved by presenter (human)`), recovery **lift** (`safe_to_lift=True`, "recovery lift allowed:
Forensics signalled safe_to_lift and containment was executed"), status **RESOLVED**. Two drafts created
(contained + resolved), both PENDING_SIGNOFF.

### Case 2 — Injection/fuzzing probe
**Incident:** `inc-de5e9f7d4605`. **Outcome:** escalated (same `credential_stuffing`/`brute_force` signal
as ordinary brute force, even though the technique was SQLi/XSS/path-traversal payloads), severity
**High**, gate **human-approved**, recovery **refusal** (`safe_to_lift=False`, "Forensics did not signal
safe_to_lift, blocks kept"), stayed **CONTAINED**. One draft PENDING_SIGNOFF.

### Case 3 — Authority-matrix denial
A forged A2A message (`source_system=customer_comms`, `action=request_action`) sent directly to the live
Containment server. **Reply:** `{"accepted": false, "reason": "authority denied for action 'request_action'
from customer_comms"}`. **Traced:** `customer_comms authority_denied blocked - request_action: DENIED (not
in the authority matrix)`. Real `check_authority` call, no LLM involved.

### Case 4 — Publish gate refuses `timeout_escalation` as approver
`comms_signoff.py approve drf-ced92bda86cb --as timeout_escalation` → refused at the sign-off endpoint
itself: `"reason": "approver 'timeout_escalation' is not a human identity"`. Draft stayed PENDING_SIGNOFF,
nothing published.

### Case 5 — Comms draft validator rejection (human edit)
`comms_signoff.py approve drf-3e0dd5a9fa40 --as presenter --edit "...203.0.113.48...db-01..."` → refused:
`"edit failed validation: contains an IPv4 address (203.0.113.48); contains an internal hostname (db-01)"`.
Real `validate_customer_text`, not published.

### Case 6 — Enumeration-only, no escalation (known gap) — **did NOT behave as documented; see Finding 1**
First attempt (run concurrently with cases 8/9/10/11/12/14's traffic) produced no incident of its own, but
that run is not valid evidence in isolation (its traffic may have been absorbed into another window).
**Clean, isolated re-run** (nothing else in flight): escalated for real as `inc-02f2f14d9cc9`,
`pattern_type=endpoint_enumeration`, confidence 0.9, reasoning: *"This rapid volume of 404 errors on a
single endpoint indicates automated profile enumeration or probing activity."* This directly contradicts
the Phase 6.1/6.2 assumption that this traffic shape reliably does not escalate — see Finding 1 below and
the `docs/BACKLOG.md` correction.

**Full resolution (same live run):** `inc-02f2f14d9cc9` went on to DISPATCHED (severity **Medium**) at
19:20:17, then the containment gate **auto-passed** — `"request_action gate: ALLOWED - no approval
required at severity=Medium"` — then RESOLVED at 19:20:36 after a recovery lift. A clean, fresh,
this-phase example of the **auto-pass gate type** (the 4th of Decision 3's four gate types), on top of
already correcting the enumeration-escalation assumption.

### Case 7 — Baseline negative control
Clean, isolated re-run (sent after case 6 settled, before case 17 started): 90 mixed requests, status
breakdown `{200: 76, 401: 14}`. **No incident was created** in the window this traffic occupied — correctly
not escalated. (The earlier concurrent attempt is not used as evidence; see the note on test-execution
contamination below.)

### Case 8 — Low-intensity, single-source brute force
`attack_simulate.py --intensity 8 --single-source`: 8 failed logins, one IP. Sent within ~1 minute of case
9's traffic; Detection's windowing merged both into a single incident (`inc-7ccd4c2e024a`) rather than
producing an independent low-severity verdict. **Reported as observed:** a true isolated Low-severity case
was not obtained — see "What wasn't cleanly isolated" below.

### Case 9 — Medium-volume, multi-IP brute force, no successes
`attack_simulate.py --intensity 18`: 18 failed logins, several IPs, no successes. Merged with case 8 into
`inc-7ccd4c2e024a`: initially assessed **High** ("Brute Force"), later real-time **reclassified to
Critical** — see Finding 2 (reclassification) below.

### Case 10 — Slow-hybrid, jittery pacing
Traffic sent (recon confirmed `alice`/`admin`/`bob`, stage 2 sent 18 slowly-paced credential-stuffing
attempts). Its traffic landed in the same aggregated window as cases 11/12/14 (`inc-6d22cef5ecc6` /
`inc-1afd00b9757c`, both Critical, both escalated) — confirms a less-bursty pacing still escalates, though
not as an independently attributable incident. Expected outcome (escalates) held.

### Case 11 — Pure credential-stuffing burst, no recon
90 login attempts straight at `alice`/`bob`/`admin`, no recon stage. Same aggregation note as case 10 —
contributed to the same escalated, Critical incidents. Expected outcome held.

### Case 12 — Containment gate opened by timeout escalation, not a human
No `--auto-ack` was passed. **All three** of the real incidents produced in this batch
(`inc-7ccd4c2e024a`, `inc-1afd00b9757c`, `inc-6d22cef5ecc6`) were in fact gated open by
`timeout_escalation`, not a human — e.g. `containment gate_evaluated timeout_escalation - request_action
gate: ALLOWED - approved by timeout_escalation (timeout_escalation)`. This happened even for the two
instances (cases 10/11) that *did* pass `--auto-ack`: Threat Assessment's real dispatch took roughly 9
minutes under rate-limit pressure, which outlasted those watcher processes' own `--watch` windows, so no
ack was ever sent in time and the system correctly fell back to its own timeout fail-safe. See Finding 3.

### Case 13 — Gate held/blocked before resolution
Captured inside case 12's incidents, e.g. `inc-7ccd4c2e024a`: `containment gate_evaluated blocked -
request_action gate: BLOCKED - approval required (severity=High) and none recorded yet`, `state:
PENDING_EVIDENCE`/`PENDING_APPROVAL`, `executed: false`, recorded ~8-13s before the timeout escalation
opened it.

### Case 14 — High-successes hybrid attack, aiming Critical + reclassification
`attack_simulate.py --intensity 40 --successes 4`: 44 requests, 5 successful logins. Landed in
`inc-1afd00b9757c`, assessed **Critical** directly (`Distributed Brute Force / Account Compromise`) —
confirming the severity-ceiling case. Its customer-comms step surfaced a **real bug** — see Finding 4
below — rather than the hoped-for reclassification (reclassification instead fired, for real, on case
8/9's incident — see Finding 2).

### Case 15 / 20 — Concurrent incidents, per-incident scoping
Three incidents (`inc-7ccd4c2e024a`, `inc-1afd00b9757c`, `inc-6d22cef5ecc6`) were genuinely, simultaneously
open for roughly 10 minutes (all created within 100 seconds of each other, 18:57:37-18:59:17, all still
CANDIDATE/DISPATCHED/CONTAINED together). Queried `/reasoning/events?incident_id=` for each: **zero
cross-contamination** — each incident's event list contained only its own `incident_id`, every time.
`/incidents/scope` correctly listed each with its own distinct IP set. A second, smaller concurrency
instance (cases 1 vs 2, sequential not overlapping) additionally confirmed isolation on older data.

### Case 16 — Cross-provider LLM fallback, observed
Real evidence from Threat Assessment's log: `gemini/gemini-flash-latest` and `gemini/gemini-2.5-flash`
both hit `litellm.RateLimitError` in sequence, and the Correlation Agent's call ultimately fell through to
and was served by **`nvidia/nemotron-3-ultra-550b-a55b:free`** (OpenRouter) — a genuine cross-provider
fallback, not just a retry on the same provider. This pattern (Gemini primary rate-limited, falling back)
recurred across most of the 20 cases; it is the dominant reason every case's wall-clock time ran far
longer than the Phase 6.1 dry-run estimate (see the time note below).

### Case 17 — Second hybrid run, clean timing sample
Fresh `attack_live.py --auto-ack` run, launched in isolation after cases 6/7's clean re-runs settled.
Produced two incidents (`inc-38f4cd1dc00f`, `inc-ca974df7cffb`) — Detection's usual split-into-two-windows
behavior for one attack, consistent with Phase 6.1/6.2 observations.

**`inc-ca974df7cffb` resolved:** severity High, dispatched ~5.5 minutes after creation (markedly faster
than cases 1-14's 9+ minute delays) — fast enough that `--auto-ack` actually won the race this time:
`on_call approval_recorded human - containment approval recorded by presenter (human)`, then `containment
gate_evaluated human - request_action gate: ALLOWED - approved by presenter (human)`, recovery lift,
RESOLVED. This is the clean confirmation for Finding 3: the auto-ack mechanism itself works correctly: it
only loses the race when real dispatch latency (rate-limit driven) outlasts the watcher's patience.
**`inc-38f4cd1dc00f` also resolved:** severity **Critical**, but dispatched 10.5 minutes after creation
(vs. its sibling's 5.5) — slow enough that `timeout_escalation` opened the gate instead: `on_call
approval_recorded timeout_escalation`, then `containment gate_evaluated timeout_escalation - request_action
gate: ALLOWED - approved by timeout_escalation`. **Two incidents from the same attack, one human-approved
and one timeout-escalated, purely from each window's own processing-queue delay** — the cleanest possible
confirmation that Finding 3 is about timing margin, not a broken auto-ack mechanism. Also recorded a
recovery-lift refusal (`Forensics did not signal safe_to_lift`) ahead of its own containment gate resolving
-- Forensics' async timing can run slightly out of step with Containment's own state, worth noting but not
investigated further this phase (not one of the Decision 5 bug criteria: no incorrect action resulted).

### Case 18 — Single honest mistake, nothing else
One `POST /login` with a wrong password, no other traffic. **No incident was created** for this request on
its own — confirms the quiet end of the non-escalation boundary.

### Case 19 — Human-edited draft that still validates, published
`comms_signoff.py approve drf-4e3b455270a8 --as priya --edit "<clean text>"` → `published: true`,
`edited_by_human: true`, `approved_by: "priya"`, `status: PUBLISHED`. The happy-path publish gate, for
real, distinct from cases 4/5's refusals.

---

## Findings

### Finding 1 — The documented "enumeration never escalates" gap is non-deterministic, not structural
**Not a bug; a correction to a previous assumption.** Phase 6.1's `docs/BACKLOG.md` entry said Detection's
window-summary fields lack any signal for enumeration-only traffic. Re-run live and in isolation in this
phase, the *identical* traffic shape was correctly classified as `endpoint_enumeration` and escalated with
0.9 confidence, using the same aggregate fields that supposedly couldn't support that conclusion. The real
issue is that the noise-filter LLM's judgment on this specific shape is inconsistent run to run, not that
the data is missing. `docs/BACKLOG.md` has been corrected (appended, original entry kept for history) —
see Task 3.

### Finding 2 — A real reclassification fired, just not on the case designed to trigger it
Case 14 (the high-successes attack, aimed at both Critical severity and reclassification) landed Critical
immediately and never reclassified (no higher severity to reclassify to). Instead, **case 9's** incident
(`inc-7ccd4c2e024a`, initially assessed High from a no-successes brute force) was reclassified to
**Critical** roughly 16 minutes later, after Forensics' evidence preservation surfaced 3 successful logins
that had occurred concurrently with the brute-force pattern but weren't part of Threat Assessment's
original window. Full real rationale captured in `status_history`: *"re-assessed on Forensics evidence:
High -> Critical... the confirmation of 3 successful logins occurring concurrently with the brute-force
attempts and reconnaissance... constituting a 'clearly successful... compromise attempt'."* This is
legitimate system behavior working exactly as designed — reclassification needs an initial under-call that
Forensics later contradicts, which a case that's Critical from the start structurally cannot produce.

### Finding 3 — `--auto-ack` can lose its race against real dispatch latency under rate limiting
Not a guardrail bug — the fail-safe worked exactly as designed — but a real operational finding. Several
incidents took ~9 minutes from CANDIDATE to DISPATCHED under heavy Gemini rate-limiting (see Finding 5 /
Case 16), which outlasted `attack_live.py`'s own `--watch` window and the auto-ack loop's attention, so the
human-equivalent ack never fired and `timeout_escalation` opened the gate instead every time. For a live
demo, this means `--auto-ack` is not a guaranteed substitute for watching the terminal when the models are
this slow.

### Finding 4 — Real bug: the deterministic template fallback can itself fail validation and crash silently
**Genuine, reproducible bug — not fixed, per Decision 5.** In Case 14 (`inc-1afd00b9757c`), the customer
notice's LLM-written draft was correctly rejected twice by `validate_customer_text` for leaking a
targeted username — "**service**" (one of `attack_simulate.py`'s `GUESS_USERNAMES`, legitimately present
in the incident's evidence because the attack guessed it as a username). On the second failure,
`customer_comms/pipeline.py`'s `build_draft()` falls back to the deterministic, code-only template — but
that template's boilerplate text *also* contains the ordinary English word "service" ("...your **service**
is currently...", "...all **services** are now..."), so `validate_customer_text` flags it too, and
`build_draft()` raises `RuntimeError("template draft failed validation: ...")` exactly as its own comment
warns ("a template that fails its own validator is a code bug"). That exception propagates uncaught out of
`asyncio.to_thread(...)` in `customer_comms/server.py`'s `_process()` — **the entire draft-creation task
crashes silently**: no draft, not even a REJECTED one, is ever created for a human to see, and the only
trace is in the process's stderr log (`"draft creation failed for inc-1afd00b9757c event=contained"`), not
surfaced to any operator.
- **Root cause:** `shared/comms_validation.py`'s `sensitive_terms()` treats every targeted username as a
  whole-word match to scrub from customer text, with no exemption for common English words that happen to
  coincide with a guessed username (`"service"` is in `attack_simulate.py`'s `GUESS_USERNAMES`). Since
  every fallback template legitimately uses the word "service" to describe, well, the service, the
  deterministic last-resort path is not actually guaranteed to succeed whenever an attacker (real or
  simulated) happens to guess that username.
- **Impact:** a customer-facing incident notification can silently fail to be created at all, for a High/
  Critical incident, with no visible error to an operator watching the dashboards.
- **Not touched this phase** per Decision 5. Added to `docs/BACKLOG.md` as a new Phase 7 item (see Task 3).

### Finding 5 — Rate limiting dominated every case's timing
Nearly every live case saw Gemini return `RateLimitError` on its primary (and often secondary) model
before falling back (Finding/Case 16), inflating CANDIDATE→DISPATCHED latency from the Phase 6.1 estimate
of 20s-5min to routinely 8-16 minutes in this run. The pre-run time estimate badly underestimated this;
see the final timing note below.

## Summary (Task 3)

**17 of 20 cases behaved as expected or produced clean, usable real evidence.** Three diverged in ways
worth separating clearly:

- **Case 6** diverged from its documented expectation (escalated instead of not escalating) — not a bug,
  a correction to a previous assumption (Finding 1), now reflected in `docs/BACKLOG.md`.
- **Case 14** surfaced a **genuine, reproducible bug** (Finding 4: the deterministic template fallback can
  itself fail validation and crash the draft-creation task silently) — reported, not fixed, added to
  `docs/BACKLOG.md`.
- **Cases 8, 10, 11** did not produce independently-attributable incidents because their traffic was sent
  close enough together that Detection's windowing merged it with other cases' traffic — a test-execution
  limitation, not a product issue; the underlying behavior they were meant to exercise (escalation at
  varying intensity, slow-hybrid pacing, pure burst) was still observed, just not in isolation.

**Two new Phase 7 backlog items** came out of this phase (both in `docs/BACKLOG.md`): the corrected
understanding of Finding 1, and the real crash bug in Finding 4. A third, minor tooling-only note (the
`run_baseline()` doc/code mismatch) was also recorded.

**Scrubbed trace table:** confirmed zero attacker IPs across all 4,439 rows in `trace_events` (the entire
project's history, not just this phase), and zero attacker-targeted usernames across this phase's 8 new
incidents specifically. The only username-shaped matches anywhere in the table are human operator
identities recorded as approvers (e.g. `alice@soc`, `priya`) — legitimate audit provenance, not leaked
customer/attacker data, and from incidents predating this phase.

## Test-execution note (not a product issue)
Cases 6-14 were launched with significant overlap (several attacks within the same ~80-second span) to
keep wall-clock time down, per the original plan. This worked well for the concurrency/scoping proof
(cases 15/20) and for exercising the gate/timeout/reclassification paths for real, but it meant Detection's
window aggregation merged several cases' traffic together, so cases 8 and 10/11 do not have independently
attributable incidents, and the first attempt at cases 6/7 was not valid in isolation. Cases 6, 7, 17, 18
and 19 were re-run or run cleanly alone specifically to get valid, isolated evidence where that mattered.


---

# Phase 6.3.5 — Real-World Tool Attack Sweep

Extends the matrix above with 10 real, independently-built security tools run against the same local
target app (never anything else), to confirm Detection's signal isn't an artifact of this project's own
simulator scripts. Two tools (THC-Hydra, Medusa) and two others (nikto, patator) could not be installed
in this Windows environment (no WSL/virtualization available for Hydra/Medusa; Windows Defender quarantined
nikto.pl and patator.py as HackTool-category files, a known, expected false-positive for real pentesting
tools, and bypassing that protection was not attempted) — each is substituted with the closest available
real tool/technique and clearly labeled, per the phase's own explicit permission to do so. `slowhttptest`'s
actual connection-exhaustion technique was substituted with a safe, real low-and-slow request-pacing test
instead, documented below — a genuine Slowloris-style attack against this app's single-process Flask dev
server risked actually hanging or crashing it, a real destructive outcome against the user's own test
environment, not merely a detection-signal test.

| # | Tool (listed) | What actually ran | Command | Result | Severity | Escalated? |
|---|---|---|---|---|---|---|
| 1 | ffuf | ffuf (as listed) — credential stuffing (`alice`, `bob`) + password spraying | see Phase 6.3.5 intro / chat history | Found `wonderland`, `builder123`, `admin`/`admin` live | Critical / Medium / High | Yes, all 3 |
| 2 | hydra | **Substitute: `curl.exe`**, sequential, one real HTTP client process per request | `for pw in $(cat passwords.txt); do curl -s -X POST .../login -H "X-Forwarded-For: 198.51.100.200" -d '{"username":"alice","password":"'$pw'"}'; done` | Found `wonderland` (real `curl/8.14.1` UA, confirmed in access.log) | High | Yes — `inc-6752ff201f73` |
| 3 | medusa | **Substitute: `curl.exe` + `xargs -P 20`**, genuine OS-level parallel brute force | `cat passwords.txt \| xargs -P 20 -I{} curl -s -X POST .../login -H "X-Forwarded-For: 198.51.100.201" -d '{"username":"bob","password":"{}"}'` | 148 requests in ~5.2s (vs ~10.5s sequential) — found `builder123` | Critical (merged w/ tool 2's tail) | Yes — `inc-66e229083af6` |
| 4 | patator | **Substitute: `gobuster fuzz`**, POST-body fuzzing, a third independent implementation | `gobuster fuzz -u .../login -w passwords.txt -m POST -B '{"username":"admin","password":"FUZZ"}' -b 401` | Found `admin`/`admin` (weak default) at word #13/148 | Critical | Yes — `inc-66e229083af6` (merged) |
| 5 | nikto | **Substitute: `gobuster dir`** with a broad misconfiguration/signature path list (43 paths: `.git/config`, `.env`, `phpinfo.php`, `wp-admin`, `server-status`, etc.) | `gobuster dir -u http://127.0.0.1:8081/ -w nikto_paths.txt -a "Mozilla/5.0 (compatible; Nikto-style-scan)"` | Only `/status` (real route) returned 200; everything else 404 — no login attempts | n/a | **No** |
| 6 | gobuster | **As listed** — `dir` mode, 89-word standard directory/file brute-force list | `gobuster dir -u http://127.0.0.1:8081/ -w dirbrute.txt` | Found real routes `/login` (405), `/account` (200), `/profile` (400) | n/a | **No** |
| 7 | wfuzz | **Substitute: `gobuster fuzz`** against `/profile?username=FUZZ` (pip install of wfuzz itself failed — `pycurl` has no working Windows build against this Python) | `gobuster fuzz -u "http://127.0.0.1:8081/profile?username=FUZZ" -w usernames.txt -b 404` | Confirmed the real IDOR: `admin`'s profile disclosed with no auth (91 usernames tried) | n/a | **No** |
| 8 | sqlmap | **As listed** — real boolean-based-blind SQLi probing against the JSON `username` field | `.venv\python sqlmap.py -u .../login --data='{"username":"*","password":"x"}' --batch --level=1 --risk=1 --technique=B --ignore-code=401,400` | Correctly concluded **not injectable** (true negative — the app does no SQL at all) | High | Yes — `inc-34ec43af2200` (its own probing traffic read as credential-stuffing-shaped) |
| 9 | nuclei | **As listed** — template-based scan, `default-login`+`exposed-panel` tags, 346 real signed templates | `nuclei -u http://127.0.0.1:8081 -tags default-login,exposed-panel` | 630 HTTP connections in 4.8s, no vulnerable template matched (correct — a custom app, not a known product). Some templates' `/login` probes (device default-creds, e.g. `netdisco`/`openplc`/`pyload`) did reach the real `/login` route and got logged | n/a (see note) | No, on its own |
| 10 | slowhttptest | **Substitute: a real, safety-conscious low-and-slow curl script** — genuine failed-login requests, one every 12s over 145s, NOT actual connection-exhaustion (see rationale above; a real Slowloris-style attack risked actually hanging this app's single-process Flask dev server) | `for pw in cobra panther jaguar ...; do curl -s -X POST .../login -H "X-Forwarded-For: 198.51.100.210" -d '{"username":"bob","password":"'$pw'"}'; sleep 12; done` | **First attempt (contaminated):** nuclei's `/login`-probing templates (above) landed in the same ~25s detection window as the first 3 requests of an earlier slow-attack attempt, and that *merged* traffic (9 failed logins, 6 usernames, 2 IPs in 24.5s) escalated as `inc-bf7e3f290434` (Critical) — not valid evidence for the slow-attack technique alone. **Clean, isolated re-run** (nothing else running): 12 failed logins, 1 account, 1 IP, over 145s (≈0.08 req/s) — **produced no incident at all**. See Finding 6 below. | n/a (isolated run) | **No — see Finding 6, a real blind spot** |


## Findings (Phase 6.3.5)

### Finding 6 — Real blind spot: a genuinely low-and-slow attack evades Detection entirely
**Confirmed, isolated, reproducible.** 12 failed logins against one account from one IP, spread over 145
seconds (~1 request every 12s, ≈0.08 req/sec) produced **zero** incidents, zero escalation, nothing in the
trace table. This is a real gap, not a merging artifact — the first attempt at this test gave a
false-positive-looking escalation only because nuclei's overlapping traffic was merged into the same
window; the clean re-run, with nothing else running, is unambiguous. Unlike Finding 1 (Phase 6.3, the
enumeration-escalation inconsistency), this is not about LLM judgment variance — Detection's window never
accumulated enough simultaneous signal to even reach the noise-filter LLM with a meaningful count, because
`detection/windowing.py`'s rolling window (`window_seconds=30.0` by default) only ever held 2-3 of the
slow attack's requests at any single evaluation, each cycle looking individually unremarkable. This is a
structural detection gap (a real missing capability, not a one-off model misjudgment) and is the strongest
single finding of this phase for Phase 7 to prioritize. Added to `docs/BACKLOG.md`.

### Note on nuclei's cross-tool interaction
Nuclei's `default-login` templates include device-specific credential checks (e.g. `netdisco`, `openplc`,
`pyload`) that POST to any `/login`-shaped path regardless of the actual product behind it — these
genuinely reached and were logged by the target app's real `/login` route, incidentally behaving like a
handful of brute-force attempts even though nuclei's actual intent was unrelated device fingerprinting.
Worth knowing if nuclei is run again near another tool: its traffic is not purely passive recon.

## Summary (Phase 6.3.5)

**6 of 10 escalated, 4 did not** (ffuf x3 all escalated, counted as one row): credential-stuffing /
brute-force variants (tools 1-4, 8) all escalated, reaching High-to-Critical every time; pure-recon tools
(5, 6, 7, 9 — nikto-substitute, gobuster dir, gobuster fuzz on `/profile`, nuclei) correctly did not
escalate, consistent with each being a GET-only, no-login-attempt traffic shape; tool 10 (low-and-slow)
did not escalate either, but for a *different and more concerning* reason — see Finding 6.

**Severities reached:** Critical (tools 3, 4, 8, and the merged slow-attack contamination), High (tools 2,
8's own incident), Medium (none new this phase). No Low severity reached (consistent with the Phase 6.3
matrix's same gap).

**Directly relevant to the enumeration investigation (Phase 6.4's prerequisite):** three independent
real tools doing pure GET-based recon (gobuster dir x2, gobuster fuzz) all landed on the **same
non-escalation** outcome as the project's own `/profile` scraper baseline — on this run, none of them
escalated, which is the ORIGINAL (Phase 6.1/6.2) expected behavior, not the one-off escalation Phase 6.3's
Finding 1 observed. This is consistent with Finding 1's own conclusion: the enumeration-only read is
LLM-judgment-dependent, not deterministic either way, and three more real-tool data points here landed on
the "does not escalate" side of that coin flip. **Finding 6 (the low-and-slow blind spot) is arguably more
load-bearing for Phase 6.4 than the enumeration question** — it is a clean, 100%-reproducible-so-far gap
with a structural cause (the window itself, not model judgment), versus enumeration's demonstrated
non-determinism.

---

## Addendum (2026-10-25) — The Three `ffuf` Runs, in Full

These ran earlier the same day as the Phase 6.3.5 sweep, at the user's request, specifically to
demonstrate a real external tool (not this project's own simulator) finding real weak credentials live.
Referenced by Phase 6.3.5's row #1; recorded here in full per Phase 6.5's prerequisite.

| Run | Target account | Wordlist | Command | Found | Attempt # | Time | Incident | Severity |
|---|---|---|---|---|---|---|---|---|
| 1 | `alice` | 148 real common weak passwords, `wonderland` planted at position 115 | `ffuf -w passwords.txt:FUZZ -u http://127.0.0.1:8081/login -X POST -H "Content-Type: application/json" -H "X-Forwarded-For: 203.0.113.99" -d '{"username":"alice","password":"FUZZ"}' -mc 200 -rate 15` | `wonderland` | #115/148 | ~9.7s | `inc-a0842a54f27d` | Critical |
| 2 | `bob` | Same 148-password list, `builder123` planted at position 81 (wordlist re-shuffled, `wonderland` removed) | Same command, `username=bob`, `X-Forwarded-For: 203.0.113.212` | `builder123` | #81/148 | ~5.3s | `inc-ecdcafda7500` | Medium |
| 3 | 91 usernames (password spray) | 91 realistic usernames, `admin` planted at position 84; fixed weak password `admin` | `ffuf -w usernames.txt:FUZZ -u http://127.0.0.1:8081/login -X POST -H "Content-Type: application/json" -H "X-Forwarded-For: 203.0.113.88" -d '{"username":"FUZZ","password":"admin"}' -mc 200 -rate 15` | `admin`/`admin` (weak default) | #84/91 | ~5.5s | `inc-bb3054d3c08a` | High |

All three were ffuf v2.3.0 (a genuine, independently-built HTTP fuzzing tool, not this project's
`attack_simulate.py`/`attack_live.py`), each confirmed live by the actual `[Status: 200]` hit line ffuf
printed at the moment of discovery, and each escalated for real through Detection → Threat Assessment →
dispatch → human-approved gate → Containment, with real reasoning text and (where captured) real
`served_by` model tags in `reasoning_events`.
