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

    # `websentinel-backend.exe --run-script <file> [args]` runs a bundled helper script (the C3 mimicry
    # server, the component unit tests) the way `python <file> [args]` would. In the frozen app
    # sys.executable is this exe, so launching it with a script path must not start a second backend.
    if len(sys.argv) > 2 and sys.argv[1] == "--run-script":
        import runpy
        script = sys.argv[2]
        sys.argv = sys.argv[2:]
        sys.path.insert(0, os.path.dirname(script))
        runpy.run_path(script, run_name="__main__")
        sys.exit(0)

    import uvicorn
    from core.main import app

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(os.environ.get("WEBSENTINEL_PORT", "8765")),
        log_level="info",
    )
