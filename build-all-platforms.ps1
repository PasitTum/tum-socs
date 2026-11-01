# ==============================================================================
# TUM-OpenSIEM Multi-Platform Sovereign Build & Packaging Pipeline
# Supports: Windows Desktop (.exe), Linux (ELF), macOS (Apple Silicon), Tablet & Mobile (PWA)
# ==============================================================================

Write-Host ">>> [1/5] Building Web & PWA Frontend..." -ForegroundColor Cyan
npm --prefix Tum.Siem.Web run build
if ($LASTEXITCODE -ne 0) { Write-Error "Frontend build failed"; exit 1 }

Write-Host ">>> [2/5] Building Windows Native Desktop Client (Electron)..." -ForegroundColor Cyan
npm --prefix Tum.Siem.Web run desktop:pack
if ($LASTEXITCODE -ne 0) { Write-Error "Desktop build failed"; exit 1 }

Write-Host ">>> [3/5] Publishing Windows Standalone Server (win-x64)..." -ForegroundColor Cyan
dotnet publish Tum.Siem.Server\Tum.Siem.Server.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o dist\win-x64
Copy-Item -Path Tum.Siem.Server\wwwroot -Destination dist\win-x64\wwwroot -Recurse -Force

Write-Host ">>> [4/5] Publishing Linux Standalone Server (linux-x64)..." -ForegroundColor Cyan
dotnet publish Tum.Siem.Server\Tum.Siem.Server.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o dist\linux-x64
Copy-Item -Path Tum.Siem.Server\wwwroot -Destination dist\linux-x64\wwwroot -Recurse -Force

Write-Host ">>> [5/5] Publishing macOS Apple Silicon Standalone Server (osx-arm64)..." -ForegroundColor Cyan
dotnet publish Tum.Siem.Server\Tum.Siem.Server.csproj -c Release -r osx-arm64 --self-contained true -p:PublishSingleFile=true -o dist\osx-arm64
Copy-Item -Path Tum.Siem.Server\wwwroot -Destination dist\osx-arm64\wwwroot -Recurse -Force

Write-Host "`n==============================================================================" -ForegroundColor Green
Write-Host " TUM-OpenSIEM MVP Build Complete for All Supported Platforms!" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host " 1. Windows Desktop App:    dist\desktop\win-unpacked\TUM-OpenSIEM.exe" -ForegroundColor Yellow
Write-Host " 2. Windows Server (.exe):  dist\win-x64\Tum.Siem.Server.exe" -ForegroundColor Yellow
Write-Host " 3. Linux Server (Binary):  dist\linux-x64\Tum.Siem.Server" -ForegroundColor Yellow
Write-Host " 4. macOS Server (Binary):  dist\osx-arm64\Tum.Siem.Server" -ForegroundColor Yellow
Write-Host " 5. Mobile & Tablet:        PWA enabled (manifest.webmanifest + sw.js)" -ForegroundColor Yellow
Write-Host "==============================================================================" -ForegroundColor Green
