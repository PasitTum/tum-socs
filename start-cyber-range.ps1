# ==============================================================================
# TUM-OpenSIEM Autonomous Cyber Range & Multi-Layer Simulator Launcher
# Starts the entire enterprise stack: Gateway, Banking Core, Database Vault, SIEM Core & UI
# ==============================================================================

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host " STARTING TUM-OPENSIEM SOVEREIGN MULTI-LAYER CYBER RANGE" -ForegroundColor Cyan
Write-Host "==============================================================================`n" -ForegroundColor Cyan

# 1. Start Cyber Range Orchestrator (Layers 1, 2, 3, 4 + Forwarder)
Write-Host ">>> Booting Multi-Layer Cyber Range (Ports 5010, 5020, 5030, 5040)..." -ForegroundColor Yellow
Start-Process -FilePath "node" -ArgumentList "cyber-range/range-orchestrator.mjs" -WindowStyle Hidden

Start-Sleep -Seconds 2

# 2. Display Status
Write-Host "`n==============================================================================" -ForegroundColor Green
Write-Host " ALL SYSTEMS OPERATIONAL - MULTI-TIER CYBER RANGE READY!" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Green
Write-Host " 🌐 Layer 1: Edge Web Gateway:     http://localhost:5010" -ForegroundColor Yellow
Write-Host " 🏦 Layer 2: Core Banking API:     http://localhost:5020" -ForegroundColor Yellow
Write-Host " 🗄️ Layer 3: DB & Canary Vault:    http://localhost:5030" -ForegroundColor Yellow
Write-Host " 🎛️ Cyber Range Control API:       http://localhost:5040/range/status" -ForegroundColor Yellow
Write-Host " 🛡️ TUM-OpenSIEM Web Console:      http://localhost:5173  (or http://localhost:5000)" -ForegroundColor Green
Write-Host " 🖥️ Windows Desktop App:           dist\desktop\win-unpacked\TUM-OpenSIEM.exe" -ForegroundColor Green
Write-Host "==============================================================================`n" -ForegroundColor Green

Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Open http://localhost:5173 in your browser (or launch TUM-OpenSIEM.exe)" -ForegroundColor White
Write-Host "2. Click '🌐 สนามจำลองไซเบอร์ (Cyber Range)' in the top header" -ForegroundColor White
Write-Host "3. Click 'ยิงโจมตี 5-Stage APT Campaign' or 'เริ่มสตรีมทราฟฟิกอัตโนมัติ'" -ForegroundColor White
Write-Host "4. Watch the real-time logs, WORM hashes, and Sigma threat alerts flow into SIEM!`n" -ForegroundColor White
