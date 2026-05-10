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

:: ── Check uvicorn ─────────────────────────────────────────────
python -m uvicorn --version >nul 2>&1
if errorlevel 1 (
    echo  [INFO] uvicorn not found. Installing requirements...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo  [ERROR] pip install failed. Run manually: pip install -r requirements.txt
        pause
        exit /b 1
    )
)

:: ── Check Playwright browsers ─────────────────────────────────
python -c "from playwright.sync_api import sync_playwright; p=sync_playwright().start(); p.stop()" >nul 2>&1
if errorlevel 1 (
    echo  [INFO] Installing Playwright Chromium browser...
    python -m playwright install chromium
)

:: ── Free port 8765 if already occupied ────────────────────────
:: Only target LISTENING entries (not TIME_WAIT / ESTABLISHED)
:: and skip PID 0 which is a kernel entry that cannot be killed.
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr /R ":8765 .*LISTENING"') do (
    if not "%%a"=="0" (
        taskkill /F /PID %%a >nul 2>&1
    )
)

echo  [OK] Starting server on http://127.0.0.1:8765
echo  [OK] API docs  ->  http://127.0.0.1:8765/docs
echo  [OK] Press Ctrl+C to stop
echo.

python -m uvicorn core.main:app --host 127.0.0.1 --port 8765

if errorlevel 1 (
    echo.
    echo  [ERROR] Server exited with an error. See output above.
    pause
)
