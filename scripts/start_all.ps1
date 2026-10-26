# Bring up every Phase 0 process, each in its own window.
#
# The two agents MUST be separate processes -- that is the whole point of the
# A2A exit criterion -- so this opens real terminals rather than running them
# as background jobs of one shell.
#
#   powershell -ExecutionPolicy Bypass -File scripts/start_all.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# Headless mode (set STACK_HEADLESS=1, or run_demo.ps1 -Headless): start every server directly with the venv's
# python -- no PowerShell window per server -- with logs under .run\logs and TEMP/TMP on the project's drive.
# Use it when the system drive is full: a fresh PowerShell session writes its profile/history to C:, which then
# fails, while a plain python process only needs TEMP.
$headless = ($env:STACK_HEADLESS -eq '1')
if ($headless) {
    $runDir = Join-Path $root '.run'
    $logDir = Join-Path $runDir 'logs'
    $tmpDir = Join-Path $root '.tmp'
    foreach ($d in $runDir, $logDir, $tmpDir) { New-Item -ItemType Directory -Force $d | Out-Null }
    $env:TEMP = $tmpDir; $env:TMP = $tmpDir; $env:OPENBLAS_NUM_THREADS = '1'
}

Write-Host "repo root: $root" -ForegroundColor Cyan

# ---- incident store ------------------------------------------------------
Write-Host "`n==> starting the incident store (Postgres on :5433)" -ForegroundColor Cyan
# Set $env:SKIP_DOCKER_STORE=1 to use a native Postgres already listening on :5433
# (user crisis / db incidents, see INCIDENT_STORE_DSN in .env) instead of Docker.
if ($env:SKIP_DOCKER_STORE -eq '1') {
    Write-Host "    SKIP_DOCKER_STORE=1: expecting a native Postgres on :5433" -ForegroundColor Yellow
} else {
    docker compose -f "$root\infra\docker-compose.yml" up -d

    Write-Host "    waiting for it to report healthy ..."
    for ($i = 0; $i -lt 30; $i++) {
        $state = docker inspect -f '{{.State.Health.Status}}' crisis-incident-store 2>$null
        if ($state -eq 'healthy') { Write-Host "    healthy" -ForegroundColor Green; break }
        Start-Sleep -Seconds 2
    }
}

# ---- the three long-running processes ------------------------------------
# Phase 1 stack: the target app, plus the two real ADK systems. The Phase 0
# hello-world scaffolds (a2a_hello.*) are superseded and no longer started;
# run them by hand if you want to re-check the Phase 0 exchange.
#
# Downstream systems start before the ones that call them: Containment and
# On-Call before Threat Assessment (it dispatches to them), and everything
# before Detection (it drives the chain).
$procs = @(
    @{ Name = 'target-app';        Venv = '.venv-app';  Args = 'target_app\app.py';              Port = 8080 },
    @{ Name = 'customer-comms';    Venv = '.venv-crew'; Args = '-m customer_comms.server';       Port = 9106 },
    @{ Name = 'forensics';         Venv = '.venv-crew'; Args = '-m forensics.server';            Port = 9105 },
    @{ Name = 'containment';       Venv = '.venv-crew'; Args = '-m containment.server';          Port = 9103 },
    @{ Name = 'on-call';           Venv = '.venv-crew'; Args = '-m on_call.server';              Port = 9104 },
    @{ Name = 'threat-assessment'; Venv = '.venv-adk';  Args = '-m threat_assessment.server';    Port = 9102 },
    @{ Name = 'detection';         Venv = '.venv-adk';  Args = '-m detection.server';            Port = 9101 },
    # Phase 5: read-only dashboard over the incident store. Not an agent system; started last so
    # it never delays the chain, and nothing depends on it.
    @{ Name = 'dashboard';         Venv = '.venv-crew'; Args = '-m dashboard.server';            Port = 8090 },
    # Phase 6: the INTERNAL, UNSANITIZED views (live access-log tail + live agent reasoning), kept on
    # their own port so nothing unscrubbed is ever served from the audit dashboard above.
    @{ Name = 'demo-internal';     Venv = '.venv-crew'; Args = '-m demo.server';                 Port = 8091 },
    # Phase 6: the branded Northwind Cloud site in front of the (unchanged) target app.
    @{ Name = 'northwind-site';    Venv = '.venv-app';  Args = '-m northwind.server';            Port = 8081 }
)

foreach ($p in $procs) {
    $py = Join-Path $root "$($p.Venv)\Scripts\python.exe"
    if (-not (Test-Path $py)) { throw "missing interpreter: $py -- see README setup" }
    Write-Host "==> starting $($p.Name) on :$($p.Port) ($($p.Venv))" -ForegroundColor Cyan
    if ($headless) {
        $log = Join-Path $logDir "$($p.Name).log"
        Start-Process -FilePath $py -ArgumentList $p.Args -WorkingDirectory $root -WindowStyle Hidden `
            -RedirectStandardOutput $log -RedirectStandardError "$log.err" | Out-Null
    } else {
        Start-Process -FilePath 'powershell' -ArgumentList @(
            '-NoExit', '-Command',
            "Set-Location '$root'; `$env:OPENBLAS_NUM_THREADS='1'; `$host.UI.RawUI.WindowTitle='$($p.Name)'; & '$py' $($p.Args)"
        ) | Out-Null
    }
}

Write-Host "`n==> waiting for all systems to answer" -ForegroundColor Cyan
$endpoints = @{
    'target-app'        = 'http://127.0.0.1:8080/status'
    'customer-comms'    = 'http://127.0.0.1:9106/health'
    'forensics'         = 'http://127.0.0.1:9105/health'
    'containment'       = 'http://127.0.0.1:9103/health'
    'on-call'           = 'http://127.0.0.1:9104/health'
    'threat-assessment' = 'http://127.0.0.1:9102/health'
    'detection'         = 'http://127.0.0.1:9101/health'
    'dashboard'         = 'http://127.0.0.1:8090/health'
    'demo-internal'     = 'http://127.0.0.1:8091/health'
    'northwind-site'    = 'http://127.0.0.1:8081/'
}

foreach ($name in $endpoints.Keys) {
    $up = $false
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $r = Invoke-WebRequest -Uri $endpoints[$name] -TimeoutSec 3 -UseBasicParsing
            if ($r.StatusCode -eq 200) { $up = $true; break }
        } catch { Start-Sleep -Seconds 2 }
    }
    if ($up) { Write-Host "    $name OK" -ForegroundColor Green }
    else     { Write-Host "    $name DID NOT COME UP -- check its window" -ForegroundColor Red }
}

Write-Host @"

Everything is up (read-only views, no auth -- local demo tools):
  Northwind Cloud (target site)         http://127.0.0.1:8081
  Trace dashboard  (scrubbed audit)     http://127.0.0.1:8090
  Live access log  (INTERNAL, raw)      http://127.0.0.1:8091/logs
  Live reasoning   (INTERNAL, raw)      http://127.0.0.1:8091/reasoning
One-command demo:  powershell -ExecutionPolicy Bypass -File scripts
un_demo.ps1 -Pattern brute-force

Drive an attack and watch the full chain:

  .\.venv-app\Scripts\python scripts\attack_simulate.py --pattern brute-force --intensity 40
  # On-Call pages; ack within the escalation window to approve:
  #   Invoke-RestMethod -Method Post "http://127.0.0.1:9104/ack?incident_id=<id>&who=you"
  # or let it time out (auto-approval). Then inspect:
  docker exec crisis-incident-store psql -U crisis -d incidents -c "SELECT incident_id,status,severity,incident_type,escalated FROM incidents ORDER BY created_at DESC LIMIT 5;"

Phase 5 checks (trace table + dashboard):
  .\.venv-adk\Scripts\python scripts	est_phase5_dashboard.py     # live attack -> trace, denials, endpoints, no-leak

Phase 4 checks (human sign-off before anything reaches customers):
  .\.venv-app\Scripts\python scripts\test_phase4_gates.py         # validator + publish gate + matrix + pipeline
  .\.venv-adk\Scripts\python scripts\test_phase4_e2e.py           # full 6-system run, sign-off via /signoff
  .\.venv-app\Scripts\python scripts\comms_signoff.py list        # pending drafts
  .\.venv-app\Scripts\python scripts\comms_signoff.py approve <draft_id> --as you
  .\.venv-app\Scripts\python scripts\comms_signoff.py reject  <draft_id> --as you --reason "..."

Phase 3 checks:
  .\.venv-app\Scripts\python scripts\test_phase3_gates.py         # evidence gate + reclassify (no LLM)
  .\.venv-adk\Scripts\python scripts\test_rca_continuation.py     # RCA mid-cutoff continuation
  .\.venv-adk\Scripts\python scripts\test_phase3_e2e.py           # Forensics + feedback loop + re-page
  .\.venv-adk\Scripts\python scripts\test_recovery_revert.py      # gated firewall revert

Phase 2 checks:
  .\.venv-adk\Scripts\python scripts\test_llm_routing.py          # provider-failure fallback (ADK)
  .\.venv-app\Scripts\python scripts\test_guardrail_block.py      # gate blocks un-approved action
  .\.venv-app\Scripts\python scripts\test_phase2_e2e.py           # full chain, both approval paths

Phase 1 checks:
  .\.venv-adk\Scripts\python scripts\test_detection_filter.py     # attack vs baseline

Phase 0 checks still pass:
  .\.venv-app\Scripts\python scripts\test_incident_store.py
  .\.venv-app\Scripts\python scripts\test_target_app.py

Stop: close the windows (or, headless: scripts\stop_all.ps1), then
  docker compose -f infra\docker-compose.yml down
"@ -ForegroundColor Cyan
