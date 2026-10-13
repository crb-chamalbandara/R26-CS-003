@echo off
REM Builds the WebSentinel Windows installer (run on Windows from the repo root).
REM Needs Python 3.10+ and Node 18+ on the BUILD machine only. Users need nothing.
REM Output: electron\dist\WebSentinel-Setup-<version>.exe
setlocal
cd /d "%~dp0"

echo [1/6] Python build environment...
if not exist .buildvenv ( python -m venv .buildvenv || goto :fail )
call .buildvenv\Scripts\activate.bat
python -m pip install --upgrade pip || goto :fail
pip install -r requirements.txt pyinstaller || goto :fail

echo [2/6] Playwright Chromium (bundled into the installer)...
REM Downloaded once and kept in dist\ms-playwright. Pass --refresh-browser to
REM wipe it and download again (e.g. after upgrading the playwright package).
if /i "%~1"=="--refresh-browser" if exist dist\ms-playwright rmdir /s /q dist\ms-playwright
set PLAYWRIGHT_BROWSERS_PATH=%CD%\dist\ms-playwright
python -m playwright install chromium || goto :fail
set PLAYWRIGHT_BROWSERS_PATH=

echo [3/6] Freezing backend with PyInstaller...
pyinstaller packaging\backend.spec --noconfirm --distpath dist --workpath build\pyi || goto :fail

echo [4/6] Freezing the C1 sandbox guest runtime (runs inside Windows Sandbox)...
REM The disposable-VM analysis needs a Python and Playwright INSIDE the VM. An installed copy has
REM neither to lend it, so the installer ships this folder (see packaging\c1_guest.spec).
pyinstaller packaging\c1_guest.spec --noconfirm --distpath dist --workpath build\pyi_guest || goto :fail
if not exist dist\c1_guest\c1-guest.exe ( echo c1_guest was not built. & goto :fail )

echo [5/6] Installing Electron dependencies...
pushd electron
REM Skip when already installed (npm ci wipes node_modules and re-downloads Electron every run).
if not exist node_modules\.bin\electron-builder.cmd (
  call npm install || (popd & goto :fail)
)

echo [6/6] Building installer...
call npm run dist || (popd & goto :fail)
popd

echo.
for %%F in (electron\dist\WebSentinel-Setup-*.exe) do echo Done. Installer: %%~fF
pause
exit /b 0

:fail
echo.
echo BUILD FAILED. Scroll up to see the error above.
pause
exit /b 1
