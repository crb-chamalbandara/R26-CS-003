@echo off
setlocal
title WebSentinel

set "APP_ROOT=%~dp0"
set "ELECTRON_APP=%APP_ROOT%electron"
set "ELECTRON_EXE=%ELECTRON_APP%\node_modules\electron\dist\electron.exe"
set "ELECTRON_CMD=%ELECTRON_APP%\node_modules\.bin\electron.cmd"
set "PYTHON_PATH=%APP_ROOT%.venv\Scripts\python.exe"

cd /d "%ELECTRON_APP%"

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

if not exist "%PYTHON_PATH%" (
    echo WARNING: venv python not found at %PYTHON_PATH%
    echo Please create the venv or set PYTHON_PATH before running.
    set "PYTHON_PATH="
)

if exist "%ELECTRON_EXE%" (
    set "ELECTRON_RUNNER=%ELECTRON_EXE%"
    set "ELECTRON_ARGS=%ELECTRON_APP%"
) else if exist "%ELECTRON_CMD%" (
    set "ELECTRON_RUNNER=%ELECTRON_CMD%"
    set "ELECTRON_ARGS=."
) else (
    echo ERROR: Electron not found. Run "npm install" in %ELECTRON_APP%.
    endlocal & exit /b 1
)

"%ELECTRON_RUNNER%" "%ELECTRON_ARGS%"
set "EXITCODE=%ERRORLEVEL%"

echo.
echo WebSentinel closed. (exit %EXITCODE%)
endlocal & exit /b %EXITCODE%
