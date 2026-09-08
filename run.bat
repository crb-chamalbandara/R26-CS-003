@echo off
:: Switch this console to UTF-8 (65001) before anything prints. Without this,
:: the console keeps its legacy OEM codepage (commonly 437), so any non-ASCII
:: character written by this script or by the Python backend it launches --
:: even though both now correctly encode as UTF-8 -- gets displayed through
:: the wrong codepage's character table instead (e.g. an em dash showing up
:: as "ΓÇö"). This only affects how this window renders text; it changes no
:: application logic.
chcp 65001 >nul
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
set ELECTRON_RUN_AS_NODE=

:: Launch the already-installed Electron binary directly instead of through
:: "npx electron .". npx resolves the local binary via an auto-generated
:: node_modules\.bin\electron.cmd shim that itself calls node.exe on a
:: further-quoted path -- an extra layer of Windows batch-file indirection
:: that is a known source of "The filename, directory name, or volume label
:: syntax is incorrect." on machines whose user profile path contains a
:: space (this one does: "Lasith Krishan"). electron\node_modules\electron
:: is guaranteed to exist by this point (installed above if missing), so
:: this reaches the exact same electron.exe the shim would have, just
:: without the extra hop -- same app, same main.js, nothing else changes.
:: npx is kept as a fallback only, in case a future Electron release moves
:: this path.
if exist "node_modules\electron\dist\electron.exe" (
    "node_modules\electron\dist\electron.exe" .
) else (
    npx electron .
)

if errorlevel 1 (
    echo.
    echo  [ERROR] Electron exited with an error. See output above.
    cd ..
    pause
)
