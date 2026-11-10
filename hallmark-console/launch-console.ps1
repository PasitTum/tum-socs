# TUM-OpenSIEM Hallmark Console Web HUD Launcher
$htmlPath = Join-Path $PSScriptRoot "index.html"
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " TUM-OpenSIEM — Hallmark Cybersecurity Visualizer" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Launching standalone zero-dependency Web HUD..." -ForegroundColor Cyan
Start-Process $htmlPath
Write-Host "[PASS] Hallmark Console opened in default browser." -ForegroundColor Green
