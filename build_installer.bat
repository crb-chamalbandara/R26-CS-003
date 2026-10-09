@echo off
REM Builds the WebSentinel Windows installer (run on Windows from the repo root).
REM Needs Python 3.10+ and Node 18+ on the BUILD machine only. Users need nothing.
REM Output: electron\dist\WebSentinel-Setup-<version>.exe
setlocal
cd /d "%~dp0"

echo [1/5] Python build environment...
if not exist .buildvenv ( python -m venv .buildvenv || goto :fail )
call .buildvenv\Scripts\activate.bat
python -m pip install --upgrade pip || goto :fail
pip install -r requirements.txt pyinstaller || goto :fail

echo [2/5] Playwright Chromium (bundled into the installer)...
REM Downloaded once and kept in dist\ms-playwright. Pass --refresh-browser to
REM wipe it and download again (e.g. after upgrading the playwright package).
if /i "%~1"=="--refresh-browser" if exist dist\ms-playwright rmdir /s /q dist\ms-playwright
set PLAYWRIGHT_BROWSERS_PATH=%CD%\dist\ms-playwright
python -m playwright install chromium || goto :fail
set PLAYWRIGHT_BROWSERS_PATH=

echo [3/5] Freezing backend with PyInstaller...
pyinstaller packaging\backend.spec --noconfirm --distpath dist --workpath build\pyi || goto :fail

echo [4/5] Installing Electron dependencies...
pushd electron
REM Skip when already installed (npm ci wipes node_modules and re-downloads Electron every run).
if not exist node_modules\.bin\electron-builder.cmd (
  call npm install || (popd & goto :fail)
)

echo [5/5] Building installer...
call npm run dist || (popd & goto :fail)
popd

echo.
echo Done. Installer: electron\dist\
pause
exit /b 0

:fail
echo.
echo BUILD FAILED. Scroll up to see the error above.
pause
exit /b 1
