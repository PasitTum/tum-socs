#!/usr/bin/env bash
# TUM-OpenSIEM Hallmark Console Web HUD Launcher (Linux / macOS)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=========================================================="
echo " TUM-OpenSIEM — Hallmark Cybersecurity Visualizer"
echo "=========================================================="
echo "Launching standalone zero-dependency Web HUD..."

if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$SCRIPT_DIR/index.html"
elif command -v open >/dev/null 2>&1; then
    open "$SCRIPT_DIR/index.html"
else
    echo "Please open $SCRIPT_DIR/index.html in your web browser."
fi
