@echo off
chcp 65001 >nul
title Aegis // Out-of-Band Router NGFW & Anti-Rootkit SOC
cd /d "%~dp0"
python -m aegis --open-browser %*
pause
