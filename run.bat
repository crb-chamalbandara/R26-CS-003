@echo off
title WebSentinel
cd /d "E:\Sliit\2023\Year 4\Sem1\Research\New Research\Code\t06-security-browser\electron"

echo ============================================
echo  WebSentinel - Starting...
echo ============================================
echo.

:: Kill any leftover backend on port 8001
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8001 " 2^>nul') do (
    taskkill /PID %%a /F >nul 2>&1
)

set ELECTRON_RUN_AS_NODE=
set PYTHONUTF8=1

node_modules\.bin\electron.cmd .

echo.
echo WebSentinel closed.
