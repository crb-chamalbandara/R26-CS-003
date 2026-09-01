@echo off
setlocal enabledelayedexpansion
title TC-01 — Cobalt Strike C2 Beacon Detection

set "APP_ROOT=%~dp0..\..\..\"
set "PYTHON=%APP_ROOT%.venv\Scripts\python.exe"
set "SCRIPT=%~dp0tc01_cobalt_strike_beacon.py"
set "BACKEND_TITLE=WebSentinel-TC01"
set "BACKEND_STARTED=0"

echo.
echo ================================================================
echo   TEST CASE 01 — Cobalt Strike C2 Beacon Detection
echo   Component: C3 — Browser Execution Aware C2 Beacon Detector
echo ================================================================
echo.
echo   This test will:
echo     1. Start the WebSentinel backend  (port 8001)
echo     2. Launch the Playwright browser session
echo     3. Establish a normal browsing baseline
echo     4. Deploy a simulated Cobalt Strike beacon (background tab)
echo     5. Monitor C3 detection in real-time
echo     6. Validate detection with pass/fail criteria
echo.
echo   Flags:
echo     --interval 30000   realistic 30s beacon interval (default: 5s fast demo)
echo     --no-baseline      skip normal browsing baseline phase
echo.
echo ================================================================
echo.

:: ── Validate Python venv ─────────────────────────────────────────────────────
if not exist "%PYTHON%" (
    echo [ERROR] Python venv not found at: %PYTHON%
    echo         Create it:  python -m venv .venv
    echo         Install:    .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

:: ── Validate test script ─────────────────────────────────────────────────────
if not exist "%SCRIPT%" (
    echo [ERROR] Test script not found: %SCRIPT%
    pause
    exit /b 1
)

:: ── Check if backend is already running ──────────────────────────────────────
"%PYTHON%" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=3)" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Backend already running on port 8001.
    goto :run_test
)

:: ── Kill leftover process on port 8001 ───────────────────────────────────────
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8001 " 2^>nul') do (
    taskkill /PID %%p /F >nul 2>&1
)

:: ── Start backend ────────────────────────────────────────────────────────────
echo [START] Launching WebSentinel backend (port 8001)...
pushd "%APP_ROOT%"
set PYTHONUTF8=1
start "%BACKEND_TITLE%" /MIN "%PYTHON%" -m uvicorn core.main:app --host 127.0.0.1 --port 8001
popd
set "BACKEND_STARTED=1"

:: ── Wait for backend ─────────────────────────────────────────────────────────
set WAITED=0
:wait_loop
if %WAITED% GEQ 45 goto :start_failed
timeout /t 2 /nobreak >nul
"%PYTHON%" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=3)" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    set /a WAITED=WAITED+2
    echo   Waiting for backend...  [!WAITED!s]
    goto :wait_loop
)
echo [OK] Backend is ready.
echo.
goto :run_test

:start_failed
echo [ERROR] Backend did not start within 45 seconds.
echo         Check the "%BACKEND_TITLE%" window for errors.
pause
exit /b 1

:: ── Run test ─────────────────────────────────────────────────────────────────
:run_test
echo [TEST] Starting TC-01...
echo.
set PYTHONUTF8=1
"%PYTHON%" -u "%SCRIPT%" %*
set "TEST_EXIT=%ERRORLEVEL%"
echo.

:: ── Cleanup ──────────────────────────────────────────────────────────────────
if "%BACKEND_STARTED%"=="1" (
    echo ================================================================
    set /p "STOP=  Stop the backend? [Y/n]: "
    if /i "!STOP!"=="n" (
        echo  Backend left running.
    ) else (
        echo  Stopping backend...
        taskkill /FI "WINDOWTITLE eq %BACKEND_TITLE%" /F >nul 2>&1
        for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8001 " 2^>nul') do (
            taskkill /PID %%p /F >nul 2>&1
        )
        echo  Done.
    )
    echo.
)

endlocal & exit /b %TEST_EXIT%
