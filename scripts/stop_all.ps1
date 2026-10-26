# Stop every demo server (the ten ports start_all.ps1 uses). Works for windowed and headless stacks.
#   powershell -ExecutionPolicy Bypass -File scripts\stop_all.ps1
foreach ($p in 8080, 9101, 9102, 9103, 9104, 9105, 9106, 8090, 8091, 8081) {
    Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
}
Write-Host "stopped anything listening on 8080, 9101-9106, 8090, 8091, 8081"
