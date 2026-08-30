@echo off
setlocal enabledelayedexpansion
title TC-03 - Real-World C2 Beacon + Live Reputation Check

set "APP_ROOT=%~dp0..\..\"
set "PYTHON=%APP_ROOT%.venv\Scripts\python.exe"
set "SCRIPT=%~dp0tc03_real_world_c2_beacon.py"
set "BACKEND_TITLE=WebSentinel-TC03"
set "BACKEND_STARTED=0"

echo.
echo ================================================================
echo   TEST CASE 03 - Real-World Infrastructure C2 Beacon
echo   Component: C3 - Browser Execution Aware C2 Beacon Detector
echo ================================================================
echo.
echo   REQUIRES: tc03_mimicry_server.py already running on infrastructure
echo   YOU own (a VPS, a free-tier cloud VM, or a tunnel). See
echo   TEST_CASE_03_Real_World_Reputation_Checked_C2_Beacon.md for setup.
echo.
echo   Usage:
echo     run_testcase_03.bat --target-host ^<your-real-ip-or-hostname^>
echo.
echo   Optional flags:
echo     --target-port 8080     (default: 8080, matches the mimicry server)
echo     --scheme https          (default: http)
echo     --interval-ms 5000      (default: 5000, beacon interval)
echo     --jitter-pct 5          (default: 5, timing jitter percent)
echo.
echo ================================================================
echo.

if "%~1"=="" (
    echo [ERROR] --target-host is required. Example:
    echo         run_testcase_03.bat --target-host 203.0.113.42
    pause
    exit /b 1
)

if not exist "%PYTHON%" (
    echo [ERROR] Python venv not found at: %PYTHON%
    echo         Create it:  python -m venv .venv
    echo         Install:    .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

if not exist "%SCRIPT%" (
    echo [ERROR] Test script not found: %SCRIPT%
    pause
    exit /b 1
)

"%PYTHON%" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=3)" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Backend already running on port 8765.
    goto :run_test
)

for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8765 " 2^>nul') do (
    taskkill /PID %%p /F >nul 2>&1
)

echo [START] Launching WebSentinel backend (port 8765)...
pushd "%APP_ROOT%"
set PYTHONUTF8=1
start "%BACKEND_TITLE%" /MIN "%PYTHON%" -m uvicorn core.main:app --host 127.0.0.1 --port 8765
popd
set "BACKEND_STARTED=1"

set WAITED=0
:wait_loop
if %WAITED% GEQ 45 goto :start_failed
timeout /t 2 /nobreak >nul
"%PYTHON%" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=3)" >nul 2>&1
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

:run_test
echo [TEST] Starting TC-03...
echo.
set PYTHONUTF8=1
"%PYTHON%" -u "%SCRIPT%" %*
set "TEST_EXIT=%ERRORLEVEL%"
echo.

if "%BACKEND_STARTED%"=="1" (
    echo ================================================================
    set /p "STOP=  Stop the backend? [Y/n]: "
    if /i "!STOP!"=="n" (
        echo  Backend left running.
    ) else (
        echo  Stopping backend...
        taskkill /FI "WINDOWTITLE eq %BACKEND_TITLE%" /F >nul 2>&1
        for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8765 " 2^>nul') do (
            taskkill /PID %%p /F >nul 2>&1
        )
        echo  Done.
    )
    echo.
)

endlocal & exit /b %TEST_EXIT%
