#!/usr/bin/env bash
# ==============================================================================
# TUM-OpenSIEM Appliance Startup Script (Linux / macOS)
# Commercial Turnkey Architecture: All-in-One SIEM + ClickHouse Columnar Sink
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo " TUM-OpenSIEM All-in-One Enterprise Appliance Launcher"
echo "=========================================================="

if command -v docker >/dev/null 2>&1; then
    echo "[INFO] Docker detected. Launching TUM-OpenSIEM Appliance containers..."
    docker compose up -d

    echo "=========================================================="
    echo " [SUCCESS] TUM-OpenSIEM Appliance Stack is Running!"
    echo "=========================================================="
    echo " - Web HUD / REST API   : http://localhost:5200"
    echo " - Syslog Ingestion     : udp://localhost:514 / tcp://localhost:514"
    echo " - ClickHouse HTTP Query: http://localhost:8123"
    echo " - ClickHouse Native    : tcp://localhost:9000"
else
    echo "[WARN] Docker engine is not detected on this host."
    echo "[INFO] Offline Appliance Archive is ready for deployment:"
    echo "       $SCRIPT_DIR/tum-opensiem-appliance-offline.tar.gz"
    echo ""
    echo "Deployment Instructions for Air-Gapped / Production Linux Host:"
    echo " 1. Extract: tar -xzvf tum-opensiem-appliance-offline.tar.gz"
    echo " 2. Launch : docker compose up -d"
fi
