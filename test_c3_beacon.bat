@echo off
setlocal enabledelayedexpansion
title C3 Beacon Detection Demo

set "APP_ROOT=%~dp0"
set "PYTHON=%APP_ROOT%.venv\Scripts\python.exe"
set "DEMO_SCRIPT=%APP_ROOT%scripts\c3_demo.py"
set "BACKEND_TITLE=WebSentinel-C3-Demo"
set "BACKEND_STARTED=0"

echo.
echo ================================================================
echo   C3 -- Browser Execution Aware C2 Beacon Detector
echo   Live Detection Demo
echo ================================================================
echo.
echo   This script will:
echo     1. Start the WebSentinel backend  (port 8001)
echo     2. Launch the Playwright browser session
echo     3. Navigate to the built-in beacon test page
echo     4. Show live C3 scores as the beacon is detected
echo.
echo   The beacon fires a POST request every 5 seconds.
echo   BEACON verdict fires after 10+ requests (approx 60-90s).
echo.
echo   Flags you can append:
echo     --interval 3000    change beacon pulse interval (ms)
echo     --no-baseline      skip the normal-browsing warm-up phase
echo.
echo ================================================================
echo.

:: ── Validate Python venv ─────────────────────────────────────────────────────
if not exist "%PYTHON%" (
    echo [ERROR] Python venv not found at:
    echo         %PYTHON%
    echo.
    echo Create and activate the venv first:
    echo   python -m venv .venv
    echo   .venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

:: ── Validate demo script ─────────────────────────────────────────────────────
if not exist "%DEMO_SCRIPT%" (
    echo [ERROR] Demo script not found: %DEMO_SCRIPT%
    echo         Make sure you are running from the project root.
    echo.
    pause
    exit /b 1
)

:: ── Check if backend is already running ──────────────────────────────────────
"%PYTHON%" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=3)" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Backend already running on port 8001  ^(will reuse it^).
    echo.
    goto :run_demo
)

:: ── Kill any leftover process on port 8001 before we start ───────────────────
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8001 " 2^>nul') do (
    taskkill /PID %%p /F >nul 2>&1
)

:: ── Start backend in a minimised window ──────────────────────────────────────
echo [START] Launching WebSentinel backend  ^(port 8001^)...
echo         A minimised window "%BACKEND_TITLE%" will open.
echo.
pushd "%APP_ROOT%"
set PYTHONUTF8=1
start "%BACKEND_TITLE%" /MIN "%PYTHON%" -m uvicorn core.main:app --host 127.0.0.1 --port 8001
popd
set "BACKEND_STARTED=1"

:: ── Wait for backend to become ready (up to 45 seconds) ──────────────────────
set WAITED=0
:wait_loop
if %WAITED% GEQ 45 goto :start_failed
timeout /t 2 /nobreak >nul
"%PYTHON%" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=3)" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    set /a WAITED=WAITED+2
    echo   Waiting for backend...  [!WAITED!s elapsed]
    goto :wait_loop
)
echo [OK] Backend is ready.
echo.
goto :run_demo

:start_failed
echo.
echo [ERROR] Backend did not start within 45 seconds.
echo         Open the minimised "%BACKEND_TITLE%" window to see the error.
echo.
echo   Common causes:
echo     - Missing Python packages  ^(run: .venv\Scripts\pip install -r requirements.txt^)
echo     - Port 8001 still in use by another process
echo     - Playwright not installed  ^(run: .venv\Scripts\playwright install chromium^)
echo.
pause
exit /b 1

:: ── Run the Python demo ───────────────────────────────────────────────────────
:run_demo
echo [DEMO] Starting C3 beacon detection demo...
echo        Press Ctrl+C at any time to stop.
echo.

set PYTHONUTF8=1
"%PYTHON%" -u "%DEMO_SCRIPT%" %*
set "DEMO_EXIT=%ERRORLEVEL%"

echo.

:: ── Cleanup: offer to stop backend only if we started it ─────────────────────
if "%BACKEND_STARTED%"=="1" (
    echo ================================================================
    set /p "STOP_BACKEND=  Stop the backend we started? [Y/n]: "
    if /i "!STOP_BACKEND!"=="n" (
        echo.
        echo  Backend left running.
        echo  To stop it: close the "%BACKEND_TITLE%" window,
        echo  or run:  taskkill /FI "WINDOWTITLE eq %BACKEND_TITLE%" /F
        echo.
    ) else (
        echo  Stopping backend...
        taskkill /FI "WINDOWTITLE eq %BACKEND_TITLE%" /F >nul 2>&1
        for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8001 " 2^>nul') do (
            taskkill /PID %%p /F >nul 2>&1
        )
        echo  Done.
        echo.
    )
)

endlocal & exit /b %DEMO_EXIT%
