<#
.SYNOPSIS
    Builds the TUM-OpenSIEM Multi-Platform Desktop Console via electron-builder.
.DESCRIPTION
    Compiles the Hallmark Console Web HUD and packages standalone desktop binaries
    for Windows, Linux, and macOS.
.PARAMETER Platform
    Target platform: 'win', 'linux', 'mac', 'dir', or 'all' (default: 'dir')
#>

param(
    [ValidateSet('win', 'linux', 'mac', 'dir', 'all')]
    [string]$Platform = 'dir'
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$webDir = Join-Path $repoRoot "Tum.Siem.Web"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " TUM-OpenSIEM Multi-Platform Desktop Console Builder" -ForegroundColor Cyan
Write-Host " Target Platform: $Platform" -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan

Set-Location $webDir

Write-Host "`n[1/2] Building Hallmark Console Web Production Bundle..." -ForegroundColor Green
npm run build

Write-Host "`n[2/2] Packaging Desktop Console via electron-builder..." -ForegroundColor Green
switch ($Platform) {
    'dir'   { npm run desktop:pack }
    'win'   { npm run desktop:build:win }
    'linux' { npm run desktop:build:linux }
    'mac'   { npm run desktop:build:mac }
    'all'   { npm run desktop:build:all }
}

$outputDir = Join-Path $repoRoot "dist\desktop"
Write-Host "`n=================================================================" -ForegroundColor Green
Write-Host " Desktop packaging completed successfully!" -ForegroundColor Green
Write-Host " Binaries located at: $outputDir" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Green
