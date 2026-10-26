# Live Demo Script (Phase 6.1 / 6.2)

Read it off, top to bottom. Every command is PowerShell, run from `D:\Agentic_Ai_Project`. Total time: about 1 minute to cold-start, then 8-12 minutes from attack to finished incident (almost all of it waiting on the models; see step 5).

## Demo login credentials (exact)

| Field | Value |
|---|---|
| URL | `http://127.0.0.1:8081/signin` |
| Username | `alice` |
| Password | `wonderland` |

This is one of the two valid accounts `attack_simulate.py` / `attack_live.py` themselves use (`VALID_CREDS`), so the attack's "successful logins" and "confirmed accounts" are this same real account. The sign-in page itself prints this pair in its demo-note banner, so a presenter who forgets does not need this document open.

## Attack patterns (Phase 6.2)

Run any of these with `scripts\attack_live.py` (adds live, colour-coded ACCESS/AGENT/STATE output in one terminal — see step 4 below) or with the older `scripts\attack_simulate.py` where noted. Pick the pattern for what you want to show, not just the default.

| `--pattern` | Shape | Expected Detection outcome | Why |
|---|---|---|---|
| `default` | Recon (enumerate usernames via the unauthenticated `/profile?username=`) then credential-stuffing against confirmed accounts, fast (~0.05s between requests) | **Escalates** — High or Critical in dry runs | The Phase 6.1 attack: a scripted, obviously-bursty two-stage compromise |
| `slow-hybrid` | The same two stages, paced slowly with random jitter instead of a fixed cadence | **Expected to escalate** (not independently confirmed via a live run this session — see Task 4) | Shows Detection is not just a burst-rate trigger; a less obviously scripted pattern should still be caught |
| `baseline` | **Negative control.** Realistic normal traffic only: a couple of valid logins, `/status` checks, one honest typo. No recon, no credential-stuffing | **Must NOT escalate** | Proves the system does not cry wolf on ordinary traffic — arguably the strongest credibility point in the whole demo |
| `burst` | Pure credential-stuffing against the real usernames, no recon stage, short and high-volume | **Escalates** | The original brute-force signal in its simplest form, just aimed at known-real accounts instead of random guesses |
| `--stage enum` (not a `--pattern`) | Recon only, no logins at all | **Does NOT escalate — a known, documented gap**, not a demo failure | Detection's window summary has no signal for enumeration-only traffic (tracked in `docs/BACKLOG.md`, Phase 7) |

Run the negative control (`--pattern baseline`) at some point in every real demo — a system that never fires is not interesting, but a system that correctly stays quiet on normal traffic, shown right next to one that fires on an attack, is the more convincing proof.

**Recommended attack:** `brute-force --intensity 40 --successes 2`. Why this one: 40 failed logins from many source IPs is an unmistakable credential attack, and the 2 *successful* logins from attacker IPs make it a confirmed compromise. In the dry runs this was rated **High or Critical** (never lower), and both ratings walk the whole six-system chain: the human-approval gate, the On-Call page, Forensics, the re-classification check and the customer notice. A plain brute force with no successes can be rated lower and skip the approval beat. Do not promise the audience "CRITICAL"; say "high-severity".

**What to expect (measured, so you are not surprised on stage):**
- Detection usually splits the attack into **two incidents about 40 seconds apart** (it analyzes the log in windows). Both are real and both walk the chain; the reasoning tab shows them interleaved (use the *incident* drop-down at the top to follow one).
- The agents take **2-5 minutes** from the attack to the first dispatch, almost all of it model latency inside Threat Assessment. Plan to talk through that wait (see step 5).

---

## 0. Before anyone is in the room (once)

```powershell
cd D:\Agentic_Ai_Project
Get-NetTCPConnection -LocalPort 5433 -State Listen | Select-Object -First 1 LocalPort
```

You should see `5433`. If you see nothing, start the Postgres service first (the incident store); nothing below works without it.

If you have already run the demo before, reset the simulated firewall too. The attack always comes from the same small pool of fake IPs, and once earlier runs have blocked them all, Containment correctly decides there is nothing left to block and the demo loses its best beat:

```powershell
Set-Content containment\firewall_state.json '{"simulated": true, "blocked": {}}'
```

## 1. Cold start (about 1-2 minutes; talk about the architecture while it comes up)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1 -NoAttack -OpenSite -Headless
```

This starts all ten services, opens four browser tabs (site, live log, live reasoning, trace dashboard) and prints this same sequence. `-Headless` runs the servers as hidden processes so there are no ten PowerShell windows on the projector. It stops with `all 10 services answering`.

## 2. Log in on the site (tab: Northwind site, `http://127.0.0.1:8081/`)

Click **Sign in**, type `alice` / `wonderland`, press **Sign in**. You land on the account dashboard (account status, usage, profile, recent sign-ins). Say: *"This is a normal customer logging in to a normal company site."*

## 3. Show the live log (tab: `http://127.0.0.1:8091/logs`)

Switch tabs. The `POST /login` (200), `GET /profile` and `GET /status` lines from the login you just did are at the bottom. Say: *"Every request to the site is one line in this log. This is the only thing the security system gets to look at."* The **"currently viewing"** line at the top says `all traffic` until an incident exists, then auto-switches to narrow this view to just that incident's own source IPs and time window (an **incident** dropdown next to it lets you pick a different one, or `all` again, by hand).

## 4. Launch the attack (this terminal)

Either the simple command:

```powershell
.\.venv-app\Scripts\python scripts\attack_simulate.py --pattern brute-force --intensity 40 --successes 2 --target-url http://127.0.0.1:8081
```

or, for a single terminal that narrates the whole thing live (the access log, every agent action and every incident-status change, in colour, as they happen) instead of switching tabs:

```powershell
.\.venv-app\Scripts\python scripts\attack_live.py --auto-ack
```

(see the pattern table above for `--pattern slow-hybrid` / `baseline` / `burst` / `--stage enum`). Either way it finishes sending in a few seconds and prints a status breakdown that is almost all `401` with two or three `200`s (the successful logins). Flip back to the log tab for a moment: once Detection opens an incident, the log view auto-scopes to just its traffic — the forty-odd lines you just sent, not the noise from everything else that has ever run on this stack.

## 5. Show the reasoning (tab: `http://127.0.0.1:8091/reasoning`)

Switch tabs. A thin **pipeline strip** at the top (Detection → Threat Assessment → Containment/On-Call/Forensics → Customer Comms) lights up the stage that just received something, so anyone can follow the chain without reading a line of text. The first card (Detection) appears within about 15 seconds; the rest fill in over the next 2-5 minutes. **This is the one long wait:** talk through it (what Detection saw, what the agents are about to do, why a human is in the loop) — and point out that a card briefly shows "**`<agent> is thinking…`**" with a dashed, pulsing border and no raw output yet, *before* it resolves into real text and a `served by <model>` tag. That is the clearest proof this is a live call, not a replay. Read the **bold plain-English line** on each resolved card; the raw agent output is underneath for anyone who wants it. An indented card with a `↳ triggered by …` line was caused by the card above it. Walk the story top to bottom:

1. **Detection** analyzed the requests and escalated.
2. **Threat Assessment** checked threat intel, classified the incident High or Critical and dispatched to Containment, On-Call and Forensics at the same moment (the three cards badged *dispatched in parallel*).
3. **Containment** planned to block the attacking IPs but is **held**: it needs evidence preserved and a human approval.
4. **On-Call** paged a human.
5. **Forensics** wrote the root-cause analysis and a recovery plan.
6. **Customer Comms** rated the customer impact and drafted a notice that cannot go out without a human.

## 6. Be the human: approve the page (this terminal)

Do this once an **On-Call** card has appeared. A page is what opens the approval gate; if you do nothing, the ~20 s timeout escalation clears it for you, which is also worth narrating. This acknowledges every incident that has been dispatched and is waiting on a human:

```powershell
(Invoke-RestMethod "http://127.0.0.1:8090/incidents?limit=5").incidents | Where-Object status -eq 'DISPATCHED' | ForEach-Object { Invoke-RestMethod -Method Post "http://127.0.0.1:9104/ack?incident_id=$($_.incident_id)&who=presenter" }
```

Each reply says `acknowledged: true, provenance: human`. Containment then runs its (simulated-firewall) block. If the command prints **nothing**, no incident is waiting any more: the ~20 s timeout escalation already cleared the gate (this happens if you are slow, and it is fine, since the card says "timeout escalation"). Move on to step 7.

## 7. Be the human again: sign off the customer notice (this terminal)

The notice shows up a few seconds after Containment acts. Show the pending drafts for the two newest incidents:

```powershell
(Invoke-RestMethod "http://127.0.0.1:8090/incidents?limit=2").incidents.incident_id | ForEach-Object { .\.venv-app\Scripts\python scripts\comms_signoff.py list --incident $_ }
```

Pick one `drf-...` id, then approve it:

```powershell
.\.venv-app\Scripts\python scripts\comms_signoff.py approve <draft_id> --as presenter
```

Replace `<draft_id>` with the id you picked. Say: *"The AI drafts the customer message; a human is the only thing that can publish it."*

## 8. Closing beat: the audited, customer-safe version (tab: `http://127.0.0.1:8090/`)

Open the newest incident. Same incident, same timeline, but scrubbed: no attacker IPs, no usernames, no raw model text, every decision and every denied action recorded. Say: *"The reasoning tab you just watched is the internal view. This is the one you can show an auditor or a customer."*

## 9. Shut down

```powershell
powershell -ExecutionPolicy Bypass -File scripts\stop_all.ps1
```

---

### If something goes wrong on stage

- **A service did not come up** at step 1: re-run the step-1 command; it only restarts what is down.
- **Reasoning tab is empty after 30 s:** the models are rate-limited or slow. Narrate the log tab and the trace dashboard (`http://127.0.0.1:8090/`), which show the incident status moving. Do not re-run the attack; wait.
- **You already ran the attack and want a clean second take:** step 9, then step 1 again.
