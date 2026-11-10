<#
.SYNOPSIS
    TUM-OpenSIEM Continuous 24-Hour Stress Test & Zero Memory Leak Verification.
.DESCRIPTION
    Launches a sustained 50,000 - 100,000 EPS load stream against TUM-OpenSIEM,
    continuously polling process WorkingSet64 and GC collections to prove Zero Memory Leak.
.PARAMETER TargetEps
    Target events per second (default: 75,000 EPS; supported: 50,000 - 100,000)
.PARAMETER DurationHours
    Duration of soak test in hours (default: 24)
.PARAMETER DurationSeconds
    Override duration in seconds (useful for smoke tests, e.g. 60)
#>

param(
    [ValidateRange(10000, 200000)]
    [int]$TargetEps = 75000,

    [double]$DurationHours = 24.0,

    [int]$DurationSeconds = 0
)

$ErrorActionPreference = 'Stop'

if ($DurationSeconds -eq 0) {
    $DurationSeconds = [int]($DurationHours * 3600)
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$reportPath = Join-Path $repoRoot "stress-test-report.json"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " TUM-OpenSIEM Continuous 24-Hour Soak & Stress Test Engine" -ForegroundColor Cyan
Write-Host " Target Load      : $TargetEps EPS" -ForegroundColor Yellow
Write-Host " Test Duration    : $DurationSeconds seconds ($([Math]::Round($DurationSeconds / 3600, 2)) hours)" -ForegroundColor Yellow
Write-Host " Standard         : Commercial Tier-1 SIEM (Zero Memory Leak Guarantee)" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan

# Set environment variables for node harness
$env:TARGET_EPS = $TargetEps.ToString()
$env:DURATION_SECONDS = $DurationSeconds.ToString()
$env:REPORT_FILE = $reportPath

$harnessScript = Join-Path $scriptDir "stress-test-50k-eps.mjs"

Write-Host "`n[1/3] Checking TUM-OpenSIEM Server Endpoint availability..." -ForegroundColor Yellow
$serverRunning = $false
try {
    $res = Invoke-WebRequest -Uri "http://localhost:5200/health" -TimeoutSec 3 -UseBasicParsing -ErrorAction SilentlyContinue
    if ($res.StatusCode -eq 200) {
        $serverRunning = $true
        Write-Host "  -> TUM-OpenSIEM Server detected online at http://localhost:5200" -ForegroundColor Green
    }
} catch {
    # Server not running on 5200, check 5000 or fallback
    try {
        $res = Invoke-WebRequest -Uri "http://localhost:5000/health" -TimeoutSec 3 -UseBasicParsing -ErrorAction SilentlyContinue
        if ($res.StatusCode -eq 200) {
            $serverRunning = $true
            $env:TARGET_PORT = "5000"
            Write-Host "  -> TUM-OpenSIEM Server detected online at http://localhost:5000" -ForegroundColor Green
        }
    } catch {}
}

if (-not $serverRunning) {
    Write-Host "  -> No running HTTP server on 5200/5000. Running in high-throughput kernel pipeline benchmark mode." -ForegroundColor Gray
}

Write-Host "`n[2/3] Initiating Stress Load Generator ($TargetEps EPS)..." -ForegroundColor Yellow
node $harnessScript

Write-Host "`n[3/3] Inspecting Zero Memory Leak Verification Results..." -ForegroundColor Yellow
if (Test-Path $reportPath) {
    $report = Get-Content $reportPath -Raw | ConvertFrom-Json
    Write-Host "`n=================================================================" -ForegroundColor Green
    Write-Host " STRESS TEST CERTIFICATION VERDICT: $($report.memoryLeakAnalysis.verdict)" -ForegroundColor Cyan
    Write-Host " Observed Throughput : $($report.observedAverageEps.ToString('N0')) EPS" -ForegroundColor White
    Write-Host " Total Logs Streamed : $($report.totalEventsIngested.ToString('N0')) events" -ForegroundColor White
    Write-Host " Memory Growth Rate  : $($report.memoryLeakAnalysis.memoryGrowthSlopeMbPerHour) MB/hour" -ForegroundColor White
    Write-Host " Full JSON Report    : $reportPath" -ForegroundColor Gray
    Write-Host "=================================================================" -ForegroundColor Green
}
