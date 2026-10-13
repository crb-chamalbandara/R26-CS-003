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

    # The packaged app has no console, so a crash would leave no trace. Keep a log file the user can send.
    if getattr(sys, "frozen", False):
        import logging.handlers
        import traceback
        log_dir = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "WebSentinel", "logs")
        try:
            os.makedirs(log_dir, exist_ok=True)
            _h = logging.handlers.RotatingFileHandler(
                os.path.join(log_dir, "backend.log"), maxBytes=1_000_000, backupCount=3, encoding="utf-8")
            _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            logging.getLogger().addHandler(_h)
            logging.getLogger().setLevel(logging.INFO)

            class _ToLog:
                def __init__(self, level): self.level = level
                def write(self, text):
                    if text and text.strip():
                        logging.getLogger("stdio").log(self.level, text.rstrip())
                def flush(self): pass
                encoding = "utf-8"
                def isatty(self): return False

            sys.stdout, sys.stderr = _ToLog(logging.INFO), _ToLog(logging.ERROR)
            sys.excepthook = lambda *a: logging.getLogger("crash").error("".join(traceback.format_exception(*a)))
        except OSError:
            pass

        # The .pkl models are version-sensitive; log what this build bundled so a mismatch with the
        # dev venv is visible next to the "[C3] ML classifier loaded" / "[L1]" lines that follow.
        import importlib
        _vers = []
        for _mod in ("xgboost", "sklearn", "numpy", "pandas", "lxml.etree"):
            try:
                _m = importlib.import_module(_mod)
                _vers.append(f"{_mod}={getattr(_m, '__version__', None) or getattr(_m, 'LXML_VERSION', '?')}")
            except Exception as _exc:
                _vers.append(f"{_mod}=MISSING({_exc.__class__.__name__})")
        print("[build] " + " ".join(_vers))

    import uvicorn
    from core.main import app

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(os.environ.get("WEBSENTINEL_PORT", "8765")),
        log_level="info",
    )
