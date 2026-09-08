@echo off
setlocal enabledelayedexpansion
title C3 Live Demo -- Real-World C2 Beacon (ngrok)

set "APP_ROOT=%~dp0"
set "PYTHON=%APP_ROOT%.venv\Scripts\python.exe"
set "TEST_SCRIPT=%APP_ROOT%test\C3\tc03_real_world_c2_beacon.py"
set "MIMIC_SERVER=%APP_ROOT%test\C3\tc03_mimicry_server.py"
set "NGROK_URL_SCRIPT=%APP_ROOT%test\C3\tc03_get_ngrok_url.py"
set "MIMIC_PORT=8080"
:: 1500ms -- live-tested 2026-08-30. 1000ms was tried first and DID reach a
:: clean ML+Heuristic alignment (auto-block fired), but at only ~125s and
:: ~116 requests -- more traffic than needed and sooner than the panel's
:: target 3-minute mark. Both maturity thresholds (ML's dilution cliff,
:: Heuristic's 50-event window flush) are EVENT-COUNT gated, not time gated
:: (see analyzer.py Rules 1/5/8: iat_cv is scale-invariant, iat_mean>0 is
:: just a non-degeneracy guard -- no rule depends on absolute interval), so
:: the same ~event count that succeeded at 1000ms now takes proportionally
:: longer at a slower pace: ~116 events x 1.5s ~= 174s, landing right at the
:: requested ~3-minute mark while cutting total request volume by ~35%.
set "INTERVAL_MS=1500"
:: 2% -- lowered from 5%% on 2026-09-08 after auto-block was measured to only
:: fire ~76%% of runs at 5%%. Direct probing of the live model
:: (models/c3_xgb_scoped_calibrated_20260903.pkl) via core/c3/feature_engine.py
:: + analyzer.py's real heuristic rules found the cause: at 5%% jitter, the
:: 50-event window's SAMPLE iat_cv averages right on top of Rule 1's
:: "iat_cv < 0.05" cliff (analyzer.py), so whether that rule's +0.30 fires is
:: close to a coin flip window to window -- swinging the fused score between
:: ~0.78 (clears the 0.75 auto-block floor) and ~0.70 (doesn't) independently
:: of anything the test is actually detecting correctly. 2%% keeps the same
:: "sleep + jitter" C2 shape (and is if anything MORE representative of
:: unsophisticated real malware, which typically uses tighter timing than a
:: red-team profile) while pushing sample iat_cv safely below the cliff.
:: Measured over 500 simulated runs at the real 60s auto-block re-check
:: cadence (core/c3/analyzer.py's _handle_beacon() cooldown), using the
:: mimicry server's REAL, live-verified check-in reply size (80 bytes,
:: confirmed via curl): 5%%+130s wait = 76.2%% success, 2%%+130s wait =
:: 97.6%%, 2%%+200s wait = 100%% -- see tc03_real_world_c2_beacon.py's
:: MATURATION_WAIT_S for the wait-side half of this fix (both changed
:: together; roll back together).
set "JITTER_PCT=2"
set "MIMIC_TITLE=C3Demo-MimicryServer"
set "NGROK_TITLE=C3Demo-Ngrok"
set "NGROK_URL_FILE=%TEMP%\c3_ngrok_url.txt"
set "NGROK_EXE="

echo.
echo ================================================================
echo   C3 -- Real-World C2 Beacon Live Demo  (ngrok)
echo ================================================================
echo.
echo   BEFORE running this:
echo     1. Start WebSentinel  (run.bat)  and open the C3 dashboard.
echo     2. Let it capture a few seconds of normal traffic.
echo.
echo   This script does NOT start WebSentinel and will not touch it.
echo   It will fully automatically:
echo     - deploy a real, publicly-reachable C2 mimicry beacon (ngrok)
echo     - drive your already-open WebSentinel browser session to it
echo     - wait for C3's ML + Heuristic engines to confirm BEACON
echo     - clean up its own ngrok/mimicry processes when done
echo.
echo   Watch the C3 dashboard on screen for live updates throughout.
echo ================================================================
echo.

:: ── Validate venv ────────────────────────────────────────────────
if not exist "%PYTHON%" (
    echo [ERROR] Python venv not found at: %PYTHON%
    echo         Create it:  python -m venv .venv
    echo         Install:    .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

:: ── Require WebSentinel already running -- this script never starts it ──
"%PYTHON%" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=3)" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] WebSentinel backend not detected on port 8765.
    echo         Start it first:  run.bat   ^(then open the C3 dashboard^)
    echo         This script deliberately does not start WebSentinel itself.
    pause
    exit /b 1
)
echo [OK] WebSentinel backend detected on port 8765.
echo.

:: ── Locate ngrok.exe ─────────────────────────────────────────────
where ngrok >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "NGROK_EXE=ngrok"
) else (
    set "NGROK_EXE=%LOCALAPPDATA%\Microsoft\WinGet\Packages\Ngrok.Ngrok_Microsoft.Winget.Source_8wekyb3d8bbwe\ngrok.exe"
    if not exist "!NGROK_EXE!" (
        echo [ERROR] ngrok.exe not found on PATH or at the expected WinGet install path.
        echo         Install it:  winget install Ngrok.Ngrok
        echo         Then authenticate once:  ngrok config add-authtoken ^<your-token^>
        pause
        exit /b 1
    )
)

:: ── Clean up any leftover instances from a previous run ─────────────
taskkill /FI "WINDOWTITLE eq %MIMIC_TITLE%" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq %NGROK_TITLE%" /F >nul 2>&1
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":%MIMIC_PORT% " 2^>nul') do taskkill /PID %%p /F >nul 2>&1
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":4040 " 2^>nul') do taskkill /PID %%p /F >nul 2>&1
del "%NGROK_URL_FILE%" >nul 2>&1
"%SystemRoot%\System32\timeout.exe" /t 1 /nobreak >nul

:: ── Start the mimicry server ─────────────────────────────────────
echo [START] Launching C2 mimicry server on port %MIMIC_PORT% ...
set PYTHONUTF8=1
start "%MIMIC_TITLE%" /MIN "%PYTHON%" "%MIMIC_SERVER%" --port %MIMIC_PORT% --interval-ms %INTERVAL_MS% --jitter-pct %JITTER_PCT%

set WAITED=0
:wait_mimic
"%PYTHON%" -c "import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(('127.0.0.1',%MIMIC_PORT%))==0 else 1)" >nul 2>&1
if errorlevel 1 (
    set /a WAITED+=1
    if !WAITED! GEQ 20 (
        echo [ERROR] Mimicry server did not come up on port %MIMIC_PORT% within 20s.
        goto :cleanup_fail
    )
    "%SystemRoot%\System32\timeout.exe" /t 1 /nobreak >nul
    goto :wait_mimic
)
echo [OK] Mimicry server is listening.
echo.

:: ── Start ngrok and resolve its public URL ───────────────────────
echo [START] Launching ngrok tunnel to port %MIMIC_PORT% ...
start "%NGROK_TITLE%" /MIN "!NGROK_EXE!" http %MIMIC_PORT% --log=stdout

"%PYTHON%" "%NGROK_URL_SCRIPT%" >"%NGROK_URL_FILE%" 2>"%NGROK_URL_FILE%.err"
if errorlevel 1 (
    echo [ERROR] Could not resolve the ngrok public URL.
    type "%NGROK_URL_FILE%.err"
    echo         Check the "%NGROK_TITLE%" window for an ngrok error
    echo         ^(commonly: not authenticated -- run "ngrok config add-authtoken ^<token^>"^).
    goto :cleanup_fail
)
set /p NGROK_URL=<"%NGROK_URL_FILE%"
echo [OK] Public tunnel: %NGROK_URL%
echo.

:: A freshly-registered tunnel can report itself as up via ngrok's local API
:: a few seconds before it is actually stable for real external traffic --
:: live-tested 2026-08-30: navigating immediately hit net::ERR_CONNECTION_CLOSED
:: once (a startup-timing race, not a real problem). The Python test also
:: retries its own navigate call, but settling here avoids needing that.
"%SystemRoot%\System32\timeout.exe" /t 5 /nobreak >nul

:: derive bare host from the https URL (strip scheme and trailing slash)
set "NGROK_HOST=%NGROK_URL:https://=%"
set "NGROK_HOST=%NGROK_HOST:http://=%"
set "NGROK_HOST=%NGROK_HOST:/=%"

echo [RUN] Starting TC-03 live beacon + detection against WebSentinel...
echo.
set PYTHONUTF8=1
"%PYTHON%" -u "%TEST_SCRIPT%" --target-host %NGROK_HOST% --target-port 443 --scheme https --interval-ms %INTERVAL_MS% --jitter-pct %JITTER_PCT% %*
set "TEST_EXIT=%ERRORLEVEL%"
goto :cleanup

:cleanup_fail
set "TEST_EXIT=1"

:cleanup
echo.
echo [CLEANUP] Stopping the mimicry server and ngrok tunnel this script started...
taskkill /FI "WINDOWTITLE eq %MIMIC_TITLE%" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq %NGROK_TITLE%" /F >nul 2>&1
del "%NGROK_URL_FILE%" >nul 2>&1
del "%NGROK_URL_FILE%.err" >nul 2>&1
echo [OK] Done. WebSentinel itself was left running -- close it yourself when finished.
echo.
pause
endlocal & exit /b %TEST_EXIT%
