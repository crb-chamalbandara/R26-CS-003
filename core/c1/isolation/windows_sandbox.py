r"""
C1 — isolation/windows_sandbox.py  |  Ephemeral virtual machine backend
------------------------------------------------------------------------
Runs the dynamic analysis inside Windows Sandbox: a lightweight Hyper-V
virtual machine that Windows builds from a clean OS image at launch and
destroys completely when it closes. Nothing inside it survives — there is no
supported way to persist state across runs, which is exactly the property a
malware sandbox wants.

This is the backend that makes the project's stated design true: the extension
package is handed to an isolated VM, the VM is created fresh for that one
analysis, and it is disposed of immediately afterwards.

How a run works
---------------
1.  Stage a per-run directory on the host:
      in\      the unpacked extension + the guest agent + the observation code
      out\     the only writable channel back to the host
2.  Generate a .wsb configuration mapping in, read-only:
      - a Python runtime            - the Playwright package tree
      - the Playwright Chromium build
      - the staged `in\` directory
    and mapping `out\` read-write.
3.  Launch `WindowsSandbox.exe run.wsb`. The guest boots, auto-logs on, and
    the LogonCommand runs the guest agent.
4.  The host polls `out\` for `result.json` until the deadline.
5.  The sandbox is torn down, taking the extension, the browser profile and
    anything the extension wrote or installed with it.

Constraints worth knowing
-------------------------
* Windows only, Pro/Enterprise/Education, feature `Containers-DisposableClientVM`.
* **Exactly one Windows Sandbox may run at a time** on a machine, so analyses
  are serialised behind a lock.
* Guest boot costs roughly 30-60 s, so a VM-isolated analysis takes far longer
  than the in-process one. That is the price of the isolation.
* Mapped folders are shared, not copied; the read-only ones cannot be modified
  by the guest, but they ARE visible to the extension under analysis. Only
  paths this module maps are exposed — never the repository or user profile.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as _xml_escape

from .base import (
    IsolationBackend, IsolationReport, unavailable_result,
    LEVEL_EPHEMERAL_VM, NET_DISABLED, NET_UNRESTRICTED,
)

# Windows Sandbox ships as an optional feature; this is its launcher.
_WSB_EXE = os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                        "System32", "WindowsSandbox.exe")
# Windows Sandbox is three layers, and the teardown order matters — the first
# live run got this wrong and orphaned a 2.5 GB VM that could not be reclaimed
# without administrator rights.
#
#   UI layer     WindowsSandbox.exe / WindowsSandboxClient.exe /
#                WindowsSandboxRemoteSession.exe — the window and its session.
#   Broker       WindowsSandboxServer.exe — owns the container's lifetime and
#                is what asks the Host Compute Service to destroy it.
#   The VM       vmmemWindowsSandbox — the container itself, managed by
#                vmcompute. Cannot be killed from an unelevated process.
#
# So: close the UI and let the broker tear the VM down. Force-killing the
# broker leaves the VM running under vmcompute with nothing left to shut it
# down, holding its memory and a lock on the mapped folders.
_WSB_UI_IMAGES     = ("WindowsSandboxClient.exe", "WindowsSandboxRemoteSession.exe",
                      "WindowsSandbox.exe")
_WSB_BROKER_IMAGE  = "WindowsSandboxServer.exe"
# The definitive "is the VM gone?" signal.
_WSB_VM_IMAGE      = "vmmemWindowsSandbox"
_WSB_ALL_IMAGES    = _WSB_UI_IMAGES + (_WSB_BROKER_IMAGE, _WSB_VM_IMAGE)

# Only one sandbox instance can exist per machine — serialise analyses.
_RUN_LOCK = asyncio.Lock()

# Fixed guest-side mount points. Short, predictable, and outside the guest's
# user profile so nothing collides with the extension's own writes.
_G_ROOT     = r"C:\c1"
_G_PYTHON   = _G_ROOT + r"\py"
_G_SITE     = _G_ROOT + r"\site"
_G_BROWSERS = _G_ROOT + r"\browsers"
_G_IN       = _G_ROOT + r"\in"
_G_OUT      = _G_ROOT + r"\out"

# How long to allow for the guest to boot and Python to start, on top of the
# caller's observation window.
# The first measured run took 162s end to end for a 20s observation window —
# guest boot, Python start and Chromium launch from mapped folders dominate,
# and they get slower when the host is short on free RAM. 150s left only 8
# seconds of margin, so a slightly slower boot would have been reported as a
# timeout. 420s is deliberately generous: a false timeout throws away a real
# analysis, while an over-long deadline only costs time on runs that already
# failed.
_BOOT_ALLOWANCE_SECONDS = 420
# The result is ready the moment the guest drops its `done` marker; a coarse
# poll just adds dead time to every analysis.
_POLL_INTERVAL_SECONDS  = 0.5

# How long to wait for the sandbox processes to actually exit after being
# killed, before giving up on deleting the staging directory.
_TEARDOWN_WAIT_SECONDS = 20.0

# How long to give the guest to shut itself down after reporting its result.
# A Windows guest powering off takes a good deal longer than a process exiting.
_SELF_SHUTDOWN_WAIT_SECONDS = 90.0


# ── Host-side dependency discovery ────────────────────────────────────────────

def _python_home() -> str:
    """The CPython installation to map into the guest.

    sys.prefix inside a venv points at the venv, whose python.exe is only a
    launcher that needs the base installation — so resolve to base_prefix.
    """
    return getattr(sys, "base_prefix", "") or sys.prefix


def _site_packages() -> str:
    """The site-packages tree holding `playwright` (and its bundled driver)."""
    try:
        import playwright
        # .../site-packages/playwright/__init__.py -> .../site-packages
        return os.path.dirname(os.path.dirname(os.path.abspath(playwright.__file__)))
    except ImportError:
        return ""


def _browsers_dir() -> str:
    """Playwright's browser download root, honouring an explicit override."""
    override = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    if override and os.path.isdir(override):
        return override
    return os.path.join(os.environ.get("LOCALAPPDATA", ""), "ms-playwright")


#: Windows Sandbox refuses to start below this, and Chromium needs headroom.
_MIN_SANDBOX_MEMORY_MB = 2048
_MAX_SANDBOX_MEMORY_MB = 4096


def _suggested_memory_mb() -> int:
    """Pick a memory cap the host can actually spare.

    A fixed 4 GB request on a machine with 2 GB free makes the guest thrash and
    the boot slow enough to look like a hang. Windows Sandbox allocates
    dynamically, so this is a ceiling, not a reservation — but keeping it under
    the free-memory figure keeps the host responsive during an analysis.
    """
    try:
        import ctypes

        class _MemoryStatusEx(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

        status = _MemoryStatusEx()
        status.dwLength = ctypes.sizeof(_MemoryStatusEx)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return _MAX_SANDBOX_MEMORY_MB
        free_mb = status.ullAvailPhys // (1024 * 1024)
        # Leave most of the free memory to the host.
        budget = int(free_mb * 0.6)
    except Exception:
        return _MAX_SANDBOX_MEMORY_MB
    return max(_MIN_SANDBOX_MEMORY_MB, min(_MAX_SANDBOX_MEMORY_MB, budget))


def _missing_dependencies() -> List[str]:
    """Everything the guest needs that we could not locate on the host."""
    missing: List[str] = []
    if not os.path.isfile(os.path.join(_python_home(), "python.exe")):
        missing.append(f"python.exe under {_python_home()}")
    if not _site_packages():
        missing.append("the playwright package")
    browsers = _browsers_dir()
    if not os.path.isdir(browsers):
        missing.append(f"Playwright browsers directory ({browsers})")
    elif not any(name.startswith("chromium") for name in os.listdir(browsers)):
        missing.append(f"a Chromium build under {browsers}")
    return missing


# ── .wsb configuration ────────────────────────────────────────────────────────

def build_wsb_config(
    *,
    staging_in: str,
    staging_out: str,
    python_home: str,
    site_packages: str,
    browsers: str,
    networking: bool,
    memory_mb: int,
) -> str:
    """Render the Windows Sandbox configuration XML for one analysis.

    Kept pure and side-effect free so it can be unit-tested without the
    Windows Sandbox feature being installed.
    """
    def folder(host: str, guest: str, read_only: bool) -> str:
        return (
            "    <MappedFolder>\n"
            f"      <HostFolder>{_xml_escape(host)}</HostFolder>\n"
            f"      <SandboxFolder>{_xml_escape(guest)}</SandboxFolder>\n"
            f"      <ReadOnly>{'true' if read_only else 'false'}</ReadOnly>\n"
            "    </MappedFolder>"
        )

    mapped = "\n".join([
        folder(python_home,   _G_PYTHON,   True),
        folder(site_packages, _G_SITE,     True),
        folder(browsers,      _G_BROWSERS, True),
        folder(staging_in,    _G_IN,       True),
        # The single writable channel back to the host.
        folder(staging_out,   _G_OUT,      False),
    ])

    # Clipboard and printer redirection are host reachback paths a malicious
    # extension could use, and nothing in the analysis needs them.
    return (
        "<Configuration>\n"
        "  <VGpu>Disable</VGpu>\n"
        f"  <Networking>{'Default' if networking else 'Disable'}</Networking>\n"
        f"  <MemoryInMB>{int(memory_mb)}</MemoryInMB>\n"
        "  <AudioInput>Disable</AudioInput>\n"
        "  <VideoInput>Disable</VideoInput>\n"
        "  <ProtectedClient>Disable</ProtectedClient>\n"
        "  <ClipboardRedirection>Disable</ClipboardRedirection>\n"
        "  <PrinterRedirection>Disable</PrinterRedirection>\n"
        "  <MappedFolders>\n"
        f"{mapped}\n"
        "  </MappedFolders>\n"
        "  <LogonCommand>\n"
        f"    <Command>{_G_IN}\\bootstrap.cmd</Command>\n"
        "  </LogonCommand>\n"
        "</Configuration>\n"
    )


def build_bootstrap_cmd(timeout_seconds: int, self_shutdown: bool = True) -> str:
    """The batch file Windows Sandbox runs on logon inside the guest.

    Writes result.json into the mapped output folder, then a `done` marker
    last — the host waits on the marker so it never reads a half-written
    result — and finally shuts the guest down.

    That last step is what makes disposal work. Windows Sandbox's container is
    owned by the Host Compute Service, and force-killing the sandbox processes
    from the host orphans it: the VM keeps running with nothing left to shut it
    down, holding ~2.5 GB and a lock on the mapped folders, and it cannot be
    terminated without administrator rights. Shutting the *guest* down from
    inside ends the container the way Windows expects, needs no privileges on
    the host, and leaves nothing behind.
    """
    lines = [
        "@echo off",
        f'set "PYTHONPATH={_G_SITE}"',
        f'set "PLAYWRIGHT_BROWSERS_PATH={_G_BROWSERS}"',
        'set "PYTHONDONTWRITEBYTECODE=1"',
        'set "PYTHONUNBUFFERED=1"',
        f'"{_G_PYTHON}\\python.exe" "{_G_IN}\\guest_agent.py" '
        f'--extension "{_G_IN}\\extension" --out "{_G_OUT}" '
        f'--timeout {int(timeout_seconds)} > "{_G_OUT}\\agent.log" 2>&1',
        f'echo %ERRORLEVEL% > "{_G_OUT}\\done"',
    ]
    if self_shutdown:
        # Give the host a moment to read the result off the mapped folder
        # before the share disappears with the guest. The host polls the `done`
        # marker twice a second, so one second is ample — and every second here
        # is a second added to every analysis.
        lines += [
            'ping -n 2 127.0.0.1 > nul',
            'shutdown /s /f /t 0',
        ]
    lines.append("")
    return "\r\n".join(lines)


# ── Backend ───────────────────────────────────────────────────────────────────

class WindowsSandboxBackend(IsolationBackend):
    name = "windows_sandbox"

    #: set by _run_blocking — whether the last VM was verifiably destroyed
    _last_teardown_verified: bool = True

    def __init__(self, network_policy: str = NET_UNRESTRICTED,
                 memory_mb: int = 0) -> None:
        self.network_policy = network_policy or NET_UNRESTRICTED
        self.memory_mb = memory_mb or _suggested_memory_mb()

    # ── availability ──────────────────────────────────────────────
    @classmethod
    def is_available(cls) -> Tuple[bool, str]:
        if sys.platform != "win32":
            return False, "Windows Sandbox exists only on Windows"
        if not os.path.isfile(_WSB_EXE):
            return False, (
                "the Windows Sandbox feature is not enabled — run as "
                "Administrator: Enable-WindowsOptionalFeature -Online "
                "-FeatureName Containers-DisposableClientVM -All  (needs a reboot)"
            )
        missing = _missing_dependencies()
        if missing:
            return False, "cannot stage the guest runtime: missing " + "; ".join(missing)
        return True, "disposable Hyper-V VM, destroyed after every analysis"

    # ── description ───────────────────────────────────────────────
    def describe(self) -> IsolationReport:
        warnings: List[str] = []
        if self.network_policy == NET_UNRESTRICTED:
            warnings.append(
                "Network egress is on, so the extension can reach live "
                "command-and-control infrastructure from this network."
            )
        warnings.append(
            "Host folders holding the runtime and the staged extension are "
            "visible read-only inside the VM."
        )
        return IsolationReport(
            backend=self.name,
            level=LEVEL_EPHEMERAL_VM,
            ephemeral=True,
            fresh_per_analysis=True,
            discarded_after=True,
            shares_host_kernel=False,
            shares_host_filesystem=False,
            shares_host_network_identity=(self.network_policy == NET_UNRESTRICTED),
            chromium_own_sandbox=False,   # --no-sandbox still required inside
            network_policy=self.network_policy,
            detail=("Windows Sandbox: a Hyper-V virtual machine built from a clean "
                    "Windows image for this analysis alone and destroyed when it "
                    "finishes. The extension never touches the host OS."),
            warnings=warnings,
        )

    # ── run ───────────────────────────────────────────────────────
    async def run(self, extension_path: str, timeout_seconds: int) -> Dict[str, Any]:
        available, reason = self.is_available()
        if not available:
            return unavailable_result(
                f"Windows Sandbox backend unavailable: {reason}", self.describe())

        ext_path = os.path.abspath(extension_path)
        if not os.path.isfile(os.path.join(ext_path, "manifest.json")):
            return unavailable_result(
                f"manifest.json not found in {ext_path}", self.describe())

        # Only one Windows Sandbox may exist per machine, so a VM left over
        # from an earlier run (or from the user's own sandbox) would make this
        # analysis fail in a confusing way. Try to clear ours first, and say
        # plainly what is wrong if it will not go.
        if await asyncio.to_thread(self.vm_is_running):
            if not await asyncio.to_thread(self._teardown):
                return unavailable_result(
                    "A Windows Sandbox VM is already running and could not be shut "
                    "down. Only one sandbox may exist at a time. Close it, or clear "
                    "an orphaned one with an elevated "
                    "'Restart-Service vmcompute -Force'.",
                    self.describe())

        # Only one Windows Sandbox may exist per machine.
        async with _RUN_LOCK:
            return await asyncio.to_thread(
                self._run_blocking, ext_path, timeout_seconds)

    # ── the blocking half, kept off the event loop ────────────────
    def _run_blocking(self, ext_path: str, timeout_seconds: int) -> Dict[str, Any]:
        report = self.describe()
        staging = tempfile.mkdtemp(prefix=f"c1_wsb_{uuid.uuid4().hex[:8]}_")
        stage_in = os.path.join(staging, "in")
        stage_out = os.path.join(staging, "out")
        started = time.time()
        launched_at = started

        try:
            os.makedirs(stage_in, exist_ok=True)
            os.makedirs(stage_out, exist_ok=True)

            # Stage the extension and the guest-side code. Only these reach
            # the VM — never the repository or the datasets.
            shutil.copytree(ext_path, os.path.join(stage_in, "extension"))
            here = os.path.dirname(os.path.abspath(__file__))
            shutil.copy2(os.path.join(here, "guest_agent.py"),
                         os.path.join(stage_in, "guest_agent.py"))
            shutil.copy2(os.path.join(os.path.dirname(here), "sandbox.py"),
                         os.path.join(stage_in, "sandbox_observer.py"))

            with open(os.path.join(stage_in, "bootstrap.cmd"), "w",
                      encoding="ascii", newline="") as handle:
                handle.write(build_bootstrap_cmd(timeout_seconds))

            wsb_path = os.path.join(staging, "run.wsb")
            with open(wsb_path, "w", encoding="utf-8") as handle:
                handle.write(build_wsb_config(
                    staging_in=stage_in,
                    staging_out=stage_out,
                    python_home=_python_home(),
                    site_packages=_site_packages(),
                    browsers=_browsers_dir(),
                    networking=(self.network_policy != NET_DISABLED),
                    memory_mb=self.memory_mb,
                ))

            # WindowsSandbox.exe returns as soon as the VM is requested, so the
            # host waits on the guest's own completion marker instead.
            launched_at = time.time()
            subprocess.Popen([_WSB_EXE, wsb_path], close_fds=True)

            deadline = started + timeout_seconds + _BOOT_ALLOWANCE_SECONDS
            marker = os.path.join(stage_out, "done")
            while time.time() < deadline and not os.path.exists(marker):
                time.sleep(_POLL_INTERVAL_SECONDS)

            timed_out = not os.path.exists(marker)
            result = self._read_result(stage_out)

            if result is None:
                detail = ("Windows Sandbox timed out before the guest reported a "
                          f"result (waited {int(time.time() - started)}s)"
                          if timed_out else
                          "Windows Sandbox finished but produced no readable result")
                result = unavailable_result(detail, report)
                result["guest_log"] = self._read_log(stage_out)

        except Exception as exc:
            result = unavailable_result(f"Windows Sandbox backend error: {exc}", report)

        # Teardown happens before the result is finalised, because whether the
        # VM was actually destroyed is part of what the result has to report.
        # The staging folders are mapped into the VM, so they cannot be deleted
        # until it is really gone.
        t_teardown_start = time.time()
        destroyed = self._teardown()
        self._remove_staging(staging)

        # Break the wall clock into phases. Guest boot is invisible from the
        # host, so it is inferred: the agent reports when it started, and
        # everything before that is boot + logon.
        phases = (result.get("guest_phases") or {}) if isinstance(result, dict) else {}
        timing = {
            "total_s":    round(time.time() - started, 1),
            "teardown_s": round(time.time() - t_teardown_start, 1),
        }
        agent_started_at = phases.get("agent_started_at")
        if agent_started_at:
            timing["guest_boot_s"] = round(float(agent_started_at) - launched_at, 1)
        for key in ("import_playwright_s", "stage_extension_s", "observe_s",
                    "agent_total_s"):
            if key in phases:
                timing[key] = phases[key]

        report.discarded_after = destroyed
        report.ephemeral = destroyed
        if not destroyed:
            report.warnings.append(
                "The sandbox VM did not shut down and is still resident. "
                "Clear it with an elevated 'Restart-Service vmcompute -Force'."
            )
        result["isolation"] = report.as_dict()
        result["isolation"]["elapsed_seconds"] = round(time.time() - started, 1)
        result["isolation"]["timing"] = timing
        return result

    @staticmethod
    def _read_result(stage_out: str) -> Optional[Dict[str, Any]]:
        path = os.path.join(stage_out, "result.json")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    @staticmethod
    def _read_log(stage_out: str, limit: int = 4000) -> str:
        try:
            with open(os.path.join(stage_out, "agent.log"), "r",
                      encoding="utf-8", errors="replace") as handle:
                return handle.read()[-limit:]
        except OSError:
            return ""

    @staticmethod
    def _running_images() -> set:
        """Which Windows Sandbox processes are alive right now."""
        try:
            out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                                 capture_output=True, timeout=20, check=False,
                                 text=True, errors="replace").stdout.lower()
        except (OSError, subprocess.SubprocessError):
            return set()
        return {img for img in _WSB_ALL_IMAGES if img.lower() in out}

    @classmethod
    def vm_is_running(cls) -> bool:
        """True while the sandbox VM itself is still resident."""
        return _WSB_VM_IMAGE in cls._running_images()

    @classmethod
    def _teardown(cls, expect_self_shutdown: bool = True) -> bool:
        """Wait for the VM to be gone, and confirm it actually is.

        Returns True only when `vmmemWindowsSandbox` has exited — that is the
        real evidence the VM was destroyed, and it is what the isolation
        report's `discarded_after` is set from. Claiming disposal we did not
        verify would be exactly the kind of unearned assertion this layer
        exists to prevent.

        The guest shuts itself down at the end of its bootstrap, so the normal
        path here is simply to wait. Force-killing is a fallback for a guest
        that never got that far (a crashed agent, a boot failure) — and it is
        genuinely a fallback, because killing the host-side processes orphans
        the container rather than destroying it.
        """
        if expect_self_shutdown:
            deadline = time.time() + _SELF_SHUTDOWN_WAIT_SECONDS
            while time.time() < deadline and cls.vm_is_running():
                time.sleep(1.0)
            if not cls.vm_is_running():
                return True
            print("[C1-WSB] Guest did not shut itself down; falling back to "
                  "closing the sandbox from the host.")

        # Fallback: close the UI and hope the broker reaps the container.
        for image in _WSB_UI_IMAGES:
            try:
                subprocess.run(["taskkill", "/IM", image, "/F", "/T"],
                               capture_output=True, timeout=30, check=False)
            except (OSError, subprocess.SubprocessError):
                pass

        deadline = time.time() + _TEARDOWN_WAIT_SECONDS
        while time.time() < deadline and cls.vm_is_running():
            time.sleep(0.5)

        if cls.vm_is_running():
            print(f"[C1-WSB] The sandbox VM ({_WSB_VM_IMAGE}) is still resident after "
                  f"teardown. It holds its memory and a lock on the staging folder, "
                  f"and cannot be terminated without administrator rights. Clear it "
                  f"with an elevated: Restart-Service vmcompute -Force")
            return False
        return True

    @staticmethod
    def _remove_staging(staging: str) -> None:
        """Delete the per-run staging directory, retrying briefly.

        Even after the sandbox processes exit, Windows can hold the mapped
        folders open for a moment; a single rmtree with ignore_errors would
        silently leak the directory (as it did on the first live run).
        """
        for attempt in range(6):
            shutil.rmtree(staging, ignore_errors=True)
            if not os.path.exists(staging):
                return
            time.sleep(1.0 + attempt)
        print(f"[C1-WSB] Could not remove staging directory {staging} — "
              f"it will need deleting manually.")
