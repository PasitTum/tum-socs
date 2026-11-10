@echo off
title TUM-OpenSIEM Hallmark Console
cd /d "%~dp0"
echo ==========================================================
echo  TUM-OpenSIEM — Hallmark Cybersecurity Visualizer
echo ==========================================================
echo Launching standalone zero-dependency Web HUD...
start "" "%~dp0index.html"
exit
