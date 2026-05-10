@echo off
setlocal enabledelayedexpansion
title TC-02 â€” Cloud APT C2 Exfiltration Beacon

set "APP_ROOT=%~dp0..\..\"
set "PYTHON=%APP_ROOT%.venv\Scripts\python.exe"
set "SCRIPT=%~dp0tc02_cloud_apt_exfiltration.py"
set "BACKEND_TITLE=WebSentinel-TC02"
set "BACKEND_STARTED=0"

echo.
echo ================================================================
echo   TEST CASE 02 â€” Cloud APT C2 Exfiltration Beacon
echo   Component: C3 â€” Browser Execution Aware C2 Beacon Detector
echo ================================================================
echo.
echo   This test will:
echo     1. Start the WebSentinel backend  (port 8001)
echo     2. Launch the Playwright browser session
echo     3. Deploy a POST exfiltration beacon (background tab)
echo     4. Actively browse other sites (user is WORKING)
echo     5. Monitor C3 detection in real-time
echo     6. Show F10 per-tab discrimination (research evidence)
echo     7. Validate detection with pass/fail criteria
echo.
echo   Key difference from TC-01:
echo     - POST method (exfiltration), not GET (check-in)
echo     - User is ACTIVELY browsing during the test
echo     - Validates F10 discrimination: beacon vs normal hosts
echo.
echo   Flags:
echo     --interval 60000   realistic 60s beacon interval (default: 8s fast demo)
echo.
echo ================================================================
echo.

:: â”€â”€ Validate Python venv â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if not exist "%PYTHON%" (
    echo [ERROR] Python venv not found at: %PYTHON%
    echo         Create it:  python -m venv .venv
    echo         Install:    .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

:: â”€â”€ Validate test script â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if not exist "%SCRIPT%" (
    echo [ERROR] Test script not found: %SCRIPT%
    pause
    exit /b 1
)

:: â”€â”€ Check if backend is already running â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
"%PYTHON%" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=3)" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Backend already running on port 8001.
    goto :run_test
)

:: â”€â”€ Kill leftover process on port 8001 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8001 " 2^>nul') do (
    taskkill /PID %%p /F >nul 2>&1
)

:: â”€â”€ Start backend â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
echo [START] Launching WebSentinel backend (port 8001)...
pushd "%APP_ROOT%"
set PYTHONUTF8=1
start "%BACKEND_TITLE%" /MIN "%PYTHON%" -m uvicorn core.main:app --host 127.0.0.1 --port 8001
popd
set "BACKEND_STARTED=1"

:: â”€â”€ Wait for backend â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

:: â”€â”€ Run test â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
:run_test
echo [TEST] Starting TC-02...
echo.
set PYTHONUTF8=1
"%PYTHON%" -u "%SCRIPT%" %*
set "TEST_EXIT=%ERRORLEVEL%"
echo.

:: â”€â”€ Cleanup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
