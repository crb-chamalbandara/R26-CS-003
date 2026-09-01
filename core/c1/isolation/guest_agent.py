"""
C1 — isolation/guest_agent.py  |  Runs INSIDE the disposable VM
------------------------------------------------------------------------
This file does not execute on the host. Windows Sandbox copies it in with the
staged extension and runs it via the .wsb LogonCommand, with:

    PYTHONPATH               -> the mapped Playwright package tree
    PLAYWRIGHT_BROWSERS_PATH -> the mapped Chromium build

It performs exactly the same observation the host-side runner performs — the
observation module is staged alongside it as `sandbox_observer.py`, so the
detection logic is identical in both places and results are comparable — then
writes `result.json` into the one writable mapped folder, which is the only
channel back to the host.

Deliberately dependency-light: standard library plus Playwright. Anything else
would have to be mapped into the guest as well.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import shutil
import sys
import time
import tempfile
import traceback


def _write(out_dir: str, name: str, payload: dict) -> None:
    """Write atomically — the host may be polling this directory."""
    final = os.path.join(out_dir, name)
    tmp = final + ".part"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)
    os.replace(tmp, final)


def _guest_facts() -> dict:
    """Evidence, collected from inside, that the analysis really ran in a guest.

    Windows Sandbox always logs on as WDAGUtilityAccount on a machine named
    for the sandbox image, so these values are what distinguish a genuine VM
    run from an accidental host run.
    """
    return {
        "hostname":      platform.node(),
        "user":          os.environ.get("USERNAME", ""),
        "os":            platform.platform(),
        "python":        sys.version.split()[0],
        "in_sandbox_account": os.environ.get("USERNAME", "").lower() == "wdagutilityaccount",
    }


async def main() -> int:
    # Phase timings, reported back with the result. Guest boot dominates the
    # wall-clock cost of a VM analysis and it is invisible from the host, so
    # the agent times its own phases and the backend subtracts to infer boot.
    t_agent_start = time.time()
    phases: dict = {}

    parser = argparse.ArgumentParser(description="C1 in-guest sandbox agent")
    parser.add_argument("--extension", required=True,
                        help="path to the unpacked extension inside the guest")
    parser.add_argument("--out", required=True,
                        help="writable mapped folder to report results into")
    parser.add_argument("--timeout", type=int, default=20,
                        help="observation window in seconds")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    # The observation module is staged next to this file by the backend.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    t_import = time.time()
    try:
        from sandbox_observer import observe_extension        # type: ignore
    except Exception as exc:
        _write(args.out, "result.json", {
            "executed": False, "score": 0, "signals": [],
            "network_requests": [], "page_signals": [],
            "detail": f"guest could not load the observation module: {exc}",
            "error": str(exc),
            "guest": _guest_facts(),
            "traceback": traceback.format_exc(),
        })
        return 2

    phases["import_playwright_s"] = round(time.time() - t_import, 2)

    # Chromium writes into an unpacked extension's directory when it loads it —
    # declarativeNetRequest rulesets are indexed on load, for one. The staged
    # extension is mapped in read-only (deliberately: the guest must not be able
    # to write back to the host), so loading it directly makes Chromium reject
    # it with "Internal error while parsing rules". Copy it to guest-local
    # storage first: writable, and destroyed with the VM either way.
    t_stage = time.time()
    ext_path = args.extension
    try:
        local = os.path.join(tempfile.gettempdir(), "c1_ext")
        shutil.rmtree(local, ignore_errors=True)
        shutil.copytree(args.extension, local)
        ext_path = local
    except Exception as exc:
        print(f"[guest] could not stage extension locally ({exc}); "
              f"loading from the read-only mapping instead", flush=True)

    phases["stage_extension_s"] = round(time.time() - t_stage, 2)

    t_observe = time.time()
    try:
        result = await observe_extension(ext_path, args.timeout)
    except Exception as exc:
        result = {
            "executed": False, "score": 0, "signals": [],
            "network_requests": [], "page_signals": [],
            "detail": f"guest observation failed: {exc}",
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }

    phases["observe_s"] = round(time.time() - t_observe, 2)
    phases["agent_total_s"] = round(time.time() - t_agent_start, 2)
    phases["agent_started_at"] = t_agent_start
    result["guest"] = _guest_facts()
    result["guest_phases"] = phases
    _write(args.out, "result.json", result)
    return 0 if result.get("executed") else 1


if __name__ == "__main__":
    if sys.platform == "win32":
        # Chromium needs the Proactor loop to spawn subprocesses on Windows.
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    raise SystemExit(asyncio.run(main()))
