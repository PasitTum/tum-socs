#!/usr/bin/env bash
# ==============================================================================
# TUM-OpenSIEM Multi-Platform Desktop Console Builder
# Packages standalone desktop console for Linux / macOS / Windows
# ==============================================================================

set -euo pipefail

TARGET="${1:-dir}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
WEB_DIR="$REPO_ROOT/Tum.Siem.Web"

echo "================================================================="
echo " TUM-OpenSIEM Multi-Platform Desktop Console Builder"
echo " Target Platform: $TARGET"
echo "================================================================="

cd "$WEB_DIR"

echo ""
echo "[1/2] Building Hallmark Console Web Production Bundle..."
npm run build

echo ""
echo "[2/2] Packaging Desktop Console via electron-builder..."
case "$TARGET" in
  dir)
    npm run desktop:pack
    ;;
  win)
    npm run desktop:build:win
    ;;
  linux)
    npm run desktop:build:linux
    ;;
  mac)
    npm run desktop:build:mac
    ;;
  all)
    npm run desktop:build:all
    ;;
  *)
    echo "Unknown target: $TARGET. Choose from: dir, win, linux, mac, all"
    exit 1
    ;;
esac

echo ""
echo "================================================================="
echo " Desktop packaging completed successfully!"
echo " Binaries located at: $REPO_ROOT/dist/desktop"
echo "================================================================="
