"""
Entry point for the packaged (PyInstaller) backend.

Electron spawns the frozen executable built from this file. In development the
backend is still launched with `python -m uvicorn core.main:app`.
"""
import multiprocessing
import os
import sys

if __name__ == "__main__":
    # Required for frozen Windows builds that use multiprocessing / joblib.
    multiprocessing.freeze_support()

    # Playwright's Chromium is shipped next to the backend inside the installer.
    if getattr(sys, "frozen", False):
        browsers = os.path.join(os.path.dirname(os.path.dirname(sys.executable)), "ms-playwright")
        if os.path.isdir(browsers):
            os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", browsers)

    import uvicorn
    from core.main import app

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(os.environ.get("WEBSENTINEL_PORT", "8765")),
        log_level="info",
    )
