# One command for the whole live demo.
#
#   powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1 -Pattern brute-force
#
# What it does:
#   1. makes sure the incident store (Postgres :5433) is reachable;
#   2. makes sure all six agent systems, the trace dashboard, the two internal views and the Northwind
#      site are up -- using the existing start_all.ps1 -- and does nothing if they already are (warm start);
#   3. opens the three views that CHANGE while an attack runs, each in its own browser tab, and prints
#      all four URLs (add -OpenSite to open the Northwind site tab as well);
#   4. runs scripts\attack_simulate.py with the pattern you chose, then prints the incident id and how
#      to ack / sign off so you can drive the human steps.
#
# Views (why three open and the fourth printed): the live access log, the live reasoning feed and the trace
# dashboard are the three that update during an attack and are meant to be watched side by side; the
# Northwind site is the *target* -- it does not change as the attack runs -- so it is printed and opened only on
# request. Four auto-opened tabs on a laptop screen are more noise than signal.
#
#   -Pattern     brute-force | burst | baseline           (default brute-force)
#   -Intensity   attack size                               (default 40)
#   -Target      site | app   attack the branded site (:8081, proxied) or the raw app (:8080)   (default site)
#   -NoBrowser   print the URLs, do not open any tab
#   -OpenSite    also open the Northwind site tab
#   -NoAttack    start/confirm everything and open the views, but do not launch an attack
#   -UseDocker   start the Postgres container via Docker instead of expecting a native Postgres on :5433
#   -Headless    start the servers as hidden processes with logs in .run\logs and TEMP on the project drive
#                (no PowerShell window per server) -- use this when the system drive (C:) is full

param(
    [ValidateSet('brute-force', 'burst', 'baseline')][string]$Pattern = 'brute-force',
    [int]$Intensity = 40,
    [ValidateSet('site', 'app')][string]$Target = 'site',
    [switch]$NoBrowser,
    [switch]$OpenSite,
    [switch]$NoAttack,
    [switch]$UseDocker,
    [switch]$Headless
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$urls = [ordered]@{
    'Northwind site (target)'          = 'http://127.0.0.1:8081/'
    'Trace dashboard (scrubbed audit)' = 'http://127.0.0.1:8090/'
    'Live access log (INTERNAL, raw)'  = 'http://127.0.0.1:8091/logs'
    'Live reasoning (INTERNAL, raw)'   = 'http://127.0.0.1:8091/reasoning'
}

# name -> health URL. Everything that must be up for a real incident to be watchable.
$checks = [ordered]@{
    'target-app'        = 'http://127.0.0.1:8080/status'
    'detection'         = 'http://127.0.0.1:9101/health'
    'threat-assessment' = 'http://127.0.0.1:9102/health'
    'containment'       = 'http://127.0.0.1:9103/health'
    'on-call'           = 'http://127.0.0.1:9104/health'
    'forensics'         = 'http://127.0.0.1:9105/health'
    'customer-comms'    = 'http://127.0.0.1:9106/health'
    'dashboard'         = 'http://127.0.0.1:8090/health'
    'demo-internal'     = 'http://127.0.0.1:8091/health'
    'northwind-site'    = 'http://127.0.0.1:8081/'
}

function Test-Up($url) {
    try { return (Invoke-WebRequest -Uri $url -TimeoutSec 3 -UseBasicParsing).StatusCode -eq 200 } catch { return $false }
}
function Get-Down() { return @($checks.Keys | Where-Object { -not (Test-Up $checks[$_]) }) }

Write-Host "`n=== Northwind demo launcher ===" -ForegroundColor Cyan

if ($Headless) {
    $env:STACK_HEADLESS = '1'
    $tmp = Join-Path $root '.tmp'
    New-Item -ItemType Directory -Force $tmp | Out-Null
    $env:TEMP = $tmp; $env:TMP = $tmp
    Write-Host "HEADLESS: servers run as hidden processes; logs in $root\.run\logs; TEMP on the project drive" -ForegroundColor Yellow
}

# ---- 1. incident store ------------------------------------------------------
if ($UseDocker) {
    Remove-Item Env:SKIP_DOCKER_STORE -ErrorAction SilentlyContinue
} else {
    $env:SKIP_DOCKER_STORE = '1'
    $pg = Test-NetConnection -ComputerName 127.0.0.1 -Port 5433 -WarningAction SilentlyContinue
    if (-not $pg.TcpTestSucceeded) {
        Write-Host "The incident store is not listening on :5433. Start the native Postgres service, or pass -UseDocker." -ForegroundColor Red
        exit 1
    }
    Write-Host "incident store reachable on :5433" -ForegroundColor Green
}

# ---- 2. services ------------------------------------------------------------
$down = Get-Down
if ($down.Count -eq 0) {
    Write-Host "WARM START: all $($checks.Count) services already up -- not touching them." -ForegroundColor Green
} else {
    $state = if ($down.Count -eq $checks.Count) { 'COLD START' } else { 'PARTIAL START' }
    Write-Host "$state : not up -> $($down -join ', ')" -ForegroundColor Yellow
    if ($down.Count -ne $checks.Count) {
        Write-Host "stopping the services that are up so start_all.ps1 can bring up a clean, consistent set ..." -ForegroundColor Yellow
        foreach ($p in 8080, 9101, 9102, 9103, 9104, 9105, 9106, 8090, 8091, 8081) {
            Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
                ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
        }
        Start-Sleep -Seconds 3
    }
    & powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'start_all.ps1')
    $still = Get-Down
    if ($still.Count -gt 0) {
        Write-Host "These did not come up: $($still -join ', ') -- check their windows." -ForegroundColor Red
        exit 1
    }
}
Write-Host "all $($checks.Count) services answering" -ForegroundColor Green

# ---- 3. views ---------------------------------------------------------------
Write-Host "`nViews:" -ForegroundColor Cyan
foreach ($k in $urls.Keys) { Write-Host ("  {0,-34} {1}" -f $k, $urls[$k]) }
if (-not $NoBrowser) {
    $open = @('Live access log (INTERNAL, raw)', 'Live reasoning (INTERNAL, raw)', 'Trace dashboard (scrubbed audit)')
    if ($OpenSite) { $open = @('Northwind site (target)') + $open }
    foreach ($k in $open) { Start-Process $urls[$k]; Start-Sleep -Milliseconds 700 }
    Write-Host "opened: $($open -join ' | ')" -ForegroundColor Green
}

if ($NoAttack) {
    Write-Host "`n-NoAttack: the stack is up and the views are reachable (and opened, unless -NoBrowser)." -ForegroundColor Cyan
    # The presenter's card -- the same sequence as docs\DEMO_SCRIPT.md, so nobody juggles two documents.
    Write-Host @"

=== WHAT TO DO NEXT (same as docs\DEMO_SCRIPT.md, steps 2-9) ===
 2. SITE tab      http://127.0.0.1:8081/signin   sign in as  alice / wonderland   -> account dashboard
 3. LOG tab       http://127.0.0.1:8091/logs     your login and page loads just appeared as access.log lines
 4. In THIS terminal, launch the attack (brute force with 2 successful logins = confirmed compromise = High or Critical):
      cd $root
      .\.venv-app\Scripts\python scripts\attack_simulate.py --pattern brute-force --intensity 40 --successes 2 --target-url http://127.0.0.1:8081
 5. REASONING tab http://127.0.0.1:8091/reasoning   read the plain-English lines top to bottom; indented = "caused by"
 6. Ack the page once an On-Call card shows (otherwise the ~20s escalation timeout clears the gate on its own):
      (Invoke-RestMethod "http://127.0.0.1:8090/incidents?limit=5").incidents | Where-Object status -eq 'DISPATCHED' | ForEach-Object { Invoke-RestMethod -Method Post "http://127.0.0.1:9104/ack?incident_id=`$(`$_.incident_id)&who=presenter" }
 7. Sign off the customer notice (Detection usually splits an attack into 2 incidents, so list both):
      (Invoke-RestMethod "http://127.0.0.1:8090/incidents?limit=2").incidents.incident_id | ForEach-Object { .\.venv-app\Scripts\python scripts\comms_signoff.py list --incident `$_ }
      .\.venv-app\Scripts\python scripts\comms_signoff.py approve <draft_id> --as presenter
 8. TRACE tab     http://127.0.0.1:8090/         the audited, scrubbed, customer-safe version of the same incident
 9. When done:    powershell -ExecutionPolicy Bypass -File scripts\stop_all.ps1
"@
    exit 0
}

# ---- 4. attack --------------------------------------------------------------
$py = Join-Path $root '.venv-app\Scripts\python.exe'
$targetUrl = if ($Target -eq 'site') { 'http://127.0.0.1:8081' } else { 'http://127.0.0.1:8080' }
$before = $null
try { $before = (Invoke-RestMethod 'http://127.0.0.1:8090/incidents?limit=1').incidents[0].incident_id } catch { }

Start-Sleep -Seconds 3   # let the browser tabs connect their streams
Write-Host "`nLaunching: attack_simulate.py --pattern $Pattern --intensity $Intensity  ->  $targetUrl" -ForegroundColor Cyan
& $py (Join-Path $PSScriptRoot 'attack_simulate.py') --pattern $Pattern --intensity $Intensity --target-url $targetUrl
$sim = $LASTEXITCODE

$iid = $null
if ($Pattern -ne 'baseline') {
    Write-Host "waiting for Detection to open an incident ..." -ForegroundColor DarkGray
    for ($i = 0; $i -lt 60 -and -not $iid; $i++) {
        Start-Sleep -Seconds 3
        try {
            $latest = (Invoke-RestMethod 'http://127.0.0.1:8090/incidents?limit=1').incidents[0].incident_id
            if ($latest -and $latest -ne $before) { $iid = $latest }
        } catch { }
    }
}

if ($iid) {
    Write-Host "`nIncident: $iid" -ForegroundColor Green
    Write-Host @"

Watch it unfold in the three tabs. The human steps are yours to drive:
  ack the page (within the ~20s escalation window; otherwise the timeout escalation clears the gate):
      Invoke-RestMethod -Method Post "http://127.0.0.1:9104/ack?incident_id=$iid&who=<you>"
  sign off the customer notice when a draft is pending:
      .\.venv-app\Scripts\python scripts\comms_signoff.py list
      .\.venv-app\Scripts\python scripts\comms_signoff.py approve <draft_id> --as <you>
"@
} elseif ($Pattern -eq 'baseline') {
    Write-Host "`nBaseline traffic sent -- Detection should NOT raise an incident (watch the live log and reasoning tabs)." -ForegroundColor Cyan
} else {
    Write-Host "`nNo new incident appeared yet (Detection may still be assessing). Check the trace dashboard." -ForegroundColor Yellow
}
exit $sim
