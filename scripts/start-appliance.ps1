# TUM-OpenSIEM Appliance Startup Script
# Commercial Turnkey Architecture: All-in-One SIEM + ClickHouse Columnar Sink
$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " TUM-OpenSIEM All-in-One Enterprise Appliance Launcher" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Check Docker CLI
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue

if ($null -ne $dockerCmd) {
    Write-Host "[INFO] Docker detected. Launching TUM-OpenSIEM Appliance containers..." -ForegroundColor Green
    
    # Check if images need to be built or loaded
    Write-Host "[INFO] Starting services via docker compose..." -ForegroundColor Cyan
    docker compose up -d

    if ($LASTEXITCODE -eq 0) {
        Write-Host "==========================================================" -ForegroundColor Green
        Write-Host " [SUCCESS] TUM-OpenSIEM Appliance Stack is Running!" -ForegroundColor Green
        Write-Host "==========================================================" -ForegroundColor Green
        Write-Host " - Web HUD / REST API   : http://localhost:5200" -ForegroundColor Cyan
        Write-Host " - Syslog Ingestion     : udp://localhost:514 / tcp://localhost:514" -ForegroundColor Cyan
        Write-Host " - ClickHouse HTTP Query: http://localhost:8123" -ForegroundColor Cyan
        Write-Host " - ClickHouse Native    : tcp://localhost:9000" -ForegroundColor Cyan
    } else {
        Write-Host "[ERROR] Failed to start docker compose stack." -ForegroundColor Red
        exit $LASTEXITCODE
    }
} else {
    Write-Host "[WARN] Docker engine is not detected on this host PATH." -ForegroundColor Yellow
    Write-Host "[INFO] Offline Appliance Archive is ready for deployment:" -ForegroundColor Cyan
    Write-Host "       $scriptDir\tum-opensiem-appliance-offline.tar.gz" -ForegroundColor White
    Write-Host ""
    Write-Host "Deployment Instructions for Air-Gapped / Production Linux Host:" -ForegroundColor Yellow
    Write-Host " 1. Copy tum-opensiem-appliance-offline.tar.gz to your Docker/Podman host."
    Write-Host " 2. Extract: tar -xzvf tum-opensiem-appliance-offline.tar.gz"
    Write-Host " 3. Launch : docker compose up -d"
    Write-Host ""
    Write-Host "To access the Web HUD without Docker on this machine, launch the standalone console:" -ForegroundColor Green
    Write-Host "       D:\TUM\setup-product\tum-socs\hallmark-console\launch-console.cmd" -ForegroundColor White
}
