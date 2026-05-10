@echo off
title WebSentinel
set "ROOT_DIR=%~dp0"
set "ELECTRON_DIR=%ROOT_DIR%electron"

echo ============================================
echo  WebSentinel - Starting...
echo ============================================
echo.

if not exist "%ELECTRON_DIR%\package.json" (
    echo Electron project folder was not found:
    echo %ELECTRON_DIR%
    exit /b 1
)

cd /d "%ELECTRON_DIR%"

if not exist "node_modules\.bin\electron.cmd" (
    echo Electron dependencies are missing. Run this first:
    echo cd /d "%ELECTRON_DIR%" ^&^& npm install
    exit /b 1
)

:: Kill any leftover backend on port 8001
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8001 " 2^>nul') do (
    taskkill /PID %%a /F >nul 2>&1
)

set ELECTRON_RUN_AS_NODE=
set PYTHONUTF8=1

node_modules\.bin\electron.cmd .

echo.
echo WebSentinel closed.
