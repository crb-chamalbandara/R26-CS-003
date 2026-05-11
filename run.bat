@echo off
title WebSentinel — All Components (C1+C2+C3+C4)
cd /d "%~dp0"

echo.
echo  =====================================================
echo   WebSentinel  ^|  Integrated Server
echo   C1 Extension Analyzer   C2 BitB Phishing Detector
echo   C3 Beacon Detector      C4 Forensic Correlator
echo  =====================================================
echo.

:: ── Check Python ──────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

:: ── Check Node.js ─────────────────────────────────────────────
node --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Node.js not found. Install Node.js 18+ from https://nodejs.org
    pause
    exit /b 1
)

:: ── Install Python requirements if needed ─────────────────────
python -m uvicorn --version >nul 2>&1
if errorlevel 1 (
    echo  [INFO] Installing Python requirements...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo  [ERROR] pip install failed. Run manually: pip install -r requirements.txt
        pause
        exit /b 1
    )
)

:: ── Install Playwright Chromium if needed ─────────────────────
python -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); p.stop()" >nul 2>&1
if errorlevel 1 (
    echo  [INFO] Installing Playwright Chromium browser...
    python -m playwright install chromium
)

:: ── Install Electron if node_modules missing ──────────────────
if not exist "electron\node_modules\electron" (
    echo  [INFO] Installing Electron...
    cd electron
    npm install
    cd ..
)

:: ── Free port 8765 if already occupied ────────────────────────
python -c "import subprocess,os,signal; r=subprocess.run('netstat -ano',shell=True,capture_output=True,text=True); [os.kill(int(l.split()[-1]),signal.SIGTERM) for l in r.stdout.splitlines() if ':8765' in l and 'LISTENING' in l and l.split()[-1]!='0']" >nul 2>&1

echo  [OK] Launching WebSentinel...
echo  [OK] Backend  ->  http://127.0.0.1:8765
echo  [OK] API docs ->  http://127.0.0.1:8765/docs
echo  [OK] Close the WebSentinel window to stop
echo.

cd electron
npx electron .

if errorlevel 1 (
    echo.
    echo  [ERROR] Electron exited with an error. See output above.
    cd ..
    pause
)
