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

    # The backend launches helper scripts as `[sys.executable, script.py, ...]`
    # (TC-03's mimicry server, the dashboard's unittest runners). In a frozen
    # build sys.executable is THIS exe, not a Python interpreter, so without this
    # the "script" would just start a second backend. Behave like `python script.py`.
    if getattr(sys, "frozen", False) and len(sys.argv) > 1 and sys.argv[1].lower().endswith(".py"):
        import runpy
        script = os.path.abspath(sys.argv[1])
        sys.argv = [script] + sys.argv[2:]
        sys.path.insert(0, os.path.dirname(script))
        runpy.run_path(script, run_name="__main__")
        sys.exit(0)

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
