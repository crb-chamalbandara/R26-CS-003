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
      - a guest runtime: on a development checkout the host's own Python and
        Playwright package tree, in an installed WebSentinel the shipped
        c1_guest folder (c1-guest.exe: Python, Playwright and the observation
        code, built by packaging/c1_guest.spec)
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
* A VM can only start when the hypervisor is running. `is_available()` checks
  that up front, so a PC with virtualization turned off in its BIOS, or one that
  has not restarted since Windows Sandbox was enabled, is told so at once rather
  than after a long wait.
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

# The installed backend has no console of its own, so every console tool it runs (tasklist,
# taskkill, PowerShell) would otherwise open and close a window on the user's screen.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Only one sandbox instance can exist per machine — serialise analyses.
_RUN_LOCK = asyncio.Lock()

# Fixed guest-side mount points. Short, predictable, and outside the guest's
# user profile so nothing collides with the extension's own writes.
_G_ROOT     = r"C:\c1"
_G_PYTHON   = _G_ROOT + r"\py"
_G_GUEST    = _G_ROOT + r"\guest"         # the shipped runtime (see _guest_bundle)
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

# The VM (or at least Windows Sandbox's broker process) appears within seconds of the launch, long
# before the guest has booted. If neither has appeared after this long, the sandbox did not start
# (a blocked policy, an error dialog waiting on the screen), and waiting out the full allowance above
# would only hide that for several minutes. Either process counts, so a Windows build that names one
# differently can never make a healthy run look dead. Probed every few seconds, and only until seen.
_VM_START_ALLOWANCE_SECONDS = 150
_VM_PROBE_INTERVAL_SECONDS  = 2
# A VM that was running and is then gone for this long, with no result, was closed or died (an error
# window, the user closing it). A guest that finishes writes its result before it goes, so a healthy
# run never looks like this. It is the VM that is watched, not the broker: after a failed start the
# broker stays alive behind the error window.
_VM_GONE_ALLOWANCE_SECONDS  = 10
# The guest's logon command creates agent.log in the shared output folder the moment it starts, so no
# agent.log after this long means the analysis never began inside the VM, whatever processes exist.
# Boot to that point measured 17 to 37 s, so this is several times the longest seen.
_GUEST_START_ALLOWANCE_SECONDS = 240

# How long to wait, before an analysis, for a sandbox that is already open to go away by itself.
_FOREIGN_SANDBOX_WAIT_SECONDS = 15

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


# ── The guest runtime ─────────────────────────────────────────────────────────
# What the VM runs the analysis with. A development checkout lends the VM its own Python and
# site-packages. An installed copy of WebSentinel has neither: its backend is a frozen program with no
# python.exe to lend. So the installer ships a ready-made runtime, c1_guest\c1-guest.exe (Python,
# Playwright and the observation code in one folder, built by packaging/c1_guest.spec), and the VM is
# lent that instead.
_GUEST_EXE_NAME = "c1-guest.exe"


def _is_frozen() -> bool:
    """True inside the installed (PyInstaller) backend."""
    return bool(getattr(sys, "frozen", False))


def _guest_bundle_candidates() -> List[str]:
    found: List[str] = []
    override = os.environ.get("C1_GUEST_DIR", "").strip()
    if override:
        found.append(override)               # also how a developer tries the installed path from a checkout
    if _is_frozen():
        # <install>\resources\backend\websentinel-backend.exe  ->  <install>\resources\c1_guest
        found.append(os.path.join(os.path.dirname(os.path.dirname(sys.executable)), "c1_guest"))
    return found


def _guest_bundle() -> str:
    """The folder holding the shipped guest runtime, or "" when there is none to use."""
    for folder in _guest_bundle_candidates():
        if os.path.isfile(os.path.join(folder, _GUEST_EXE_NAME)):
            return folder
    return ""


# ── Can a VM start on this PC at all? ────────────────────────────────────────
# Windows Sandbox is a Hyper-V virtual machine, so it needs the hypervisor to be running. Two things
# stop that and both look, from here, like a sandbox that "just never answers": virtualization turned
# off in the BIOS, and a PC that has not restarted since the feature was enabled. Asking first turns
# a multi-minute wait into a one-line reason. The answer is cached briefly: it is asked for on every
# analysis and every time the dashboard shows the containment status.
_PREFLIGHT_TTL_SECONDS = 30.0
_preflight_cache: Dict[str, Any] = {"at": 0.0, "problem": ""}


def _hypervisor_running() -> Optional[bool]:
    """Whether Windows is running with its hypervisor. None when that could not be established."""
    powershell = os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                              "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    try:
        out = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command",
             "(Get-CimInstance Win32_ComputerSystem).HypervisorPresent"],
            capture_output=True, text=True, timeout=30, check=False,
            creationflags=_NO_WINDOW).stdout.strip().lower()
    except (OSError, subprocess.SubprocessError):
        return None
    return {"true": True, "false": False}.get(out)


def _firmware_virtualization_on() -> bool:
    """Whether virtualization is enabled in the firmware (PF_VIRT_FIRMWARE_ENABLED)."""
    try:
        import ctypes
        return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(21))
    except Exception:
        return True                      # cannot tell: do not blame the BIOS


def _virtualization_problem() -> str:
    """The empty string when a VM can start, otherwise a plain sentence saying what stops it.

    Conservative on purpose: it only reports a problem it is sure of. If the hypervisor state cannot
    be read it says nothing, and the run itself will find out.
    """
    now = time.monotonic()
    if now - _preflight_cache["at"] < _PREFLIGHT_TTL_SECONDS and _preflight_cache["at"]:
        return _preflight_cache["problem"]
    problem = ""
    if _hypervisor_running() is False:
        if not _firmware_virtualization_on():
            problem = ("virtualization is turned off in this PC's BIOS or UEFI settings (Intel VT-x or AMD-V). "
                       "Turn it on, restart, and Windows Sandbox will be used")
        else:
            problem = ("Windows' hypervisor is not running. If Windows Sandbox was only just turned on, "
                       "restart Windows and it will be used")
    _preflight_cache.update(at=now, problem=problem)
    return problem


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
    if _guest_bundle():
        pass                                  # the shipped runtime brings its own Python and Playwright
    elif _is_frozen() or os.environ.get("C1_GUEST_DIR", "").strip():
        missing.append(f"the guest runtime ({_GUEST_EXE_NAME} in a c1_guest folder). "
                       "Reinstalling WebSentinel restores it")
    else:
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


def _new_staging_dir() -> str:
    """A fresh folder under the temp directory for one run, which Windows Sandbox is able to open.

    Not tempfile.mkdtemp(). Since Python 3.12 that gives the folder a permission list naming only the
    creator, SYSTEM and Administrators. Normally the creator is the user and that is fine. When
    WebSentinel runs as administrator the "creator" is the Administrators group, so the folder can
    then only be opened by an elevated process, while Windows Sandbox runs with the user's normal
    rights and fails with "Access is denied (0x80070005)". A plain mkdir inherits the temp folder's
    permissions, which name the user explicitly, so it works whether or not the app is elevated.
    """
    base = tempfile.gettempdir()
    for _ in range(20):
        path = os.path.join(base, f"c1_wsb_{uuid.uuid4().hex[:8]}_{uuid.uuid4().hex[:8]}")
        try:
            os.mkdir(path)
            return path
        except FileExistsError:
            continue
    raise OSError(f"could not create a staging folder under {base}")


# ── .wsb configuration ────────────────────────────────────────────────────────

def build_wsb_config(
    *,
    staging_in: str,
    staging_out: str,
    python_home: str = "",
    site_packages: str = "",
    browsers: str,
    networking: bool,
    memory_mb: int,
    guest_bundle: str = "",
) -> str:
    """Render the Windows Sandbox configuration XML for one analysis.

    The runtime is either the shipped guest bundle (`guest_bundle`) or, on a development checkout, the
    host's Python and site-packages. Kept pure and side-effect free so it can be unit-tested without
    the Windows Sandbox feature being installed.
    """
    def folder(host: str, guest: str, read_only: bool) -> str:
        return (
            "    <MappedFolder>\n"
            f"      <HostFolder>{_xml_escape(host)}</HostFolder>\n"
            f"      <SandboxFolder>{_xml_escape(guest)}</SandboxFolder>\n"
            f"      <ReadOnly>{'true' if read_only else 'false'}</ReadOnly>\n"
            "    </MappedFolder>"
        )

    runtime = ([folder(guest_bundle, _G_GUEST, True)] if guest_bundle else
               [folder(python_home, _G_PYTHON, True), folder(site_packages, _G_SITE, True)])
    mapped = "\n".join(runtime + [
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


def build_bootstrap_cmd(timeout_seconds: int, self_shutdown: bool = True,
                        bundled: bool = False) -> str:
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
    if bundled:
        # the shipped runtime carries its own Python and Playwright: only the browsers need pointing at
        environment = [
            f'set "PLAYWRIGHT_BROWSERS_PATH={_G_BROWSERS}"',
            'set "PYTHONUNBUFFERED=1"',
        ]
        agent = f'"{_G_GUEST}\\{_GUEST_EXE_NAME}" '
    else:
        environment = [
            f'set "PYTHONPATH={_G_SITE}"',
            f'set "PLAYWRIGHT_BROWSERS_PATH={_G_BROWSERS}"',
            'set "PYTHONDONTWRITEBYTECODE=1"',
            'set "PYTHONUNBUFFERED=1"',
        ]
        agent = f'"{_G_PYTHON}\\python.exe" "{_G_IN}\\guest_agent.py" '
    lines = [
        "@echo off",
        *environment,
        agent +
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
            if _is_frozen():
                return False, (
                    "Windows Sandbox is not turned on. Turn it on in Windows Features "
                    "(Turn Windows features on or off) or run the WebSentinel installer "
                    "again and tick the Windows Sandbox option, then restart Windows"
                )
            return False, (
                "the Windows Sandbox feature is not enabled. Run as "
                "Administrator: Enable-WindowsOptionalFeature -Online "
                "-FeatureName Containers-DisposableClientVM -All  (needs a reboot)"
            )
        missing = _missing_dependencies()
        if missing:
            return False, "cannot stage the guest runtime: missing " + "; ".join(missing)
        problem = _virtualization_problem()
        if problem:
            return False, problem
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

        # Only one Windows Sandbox may exist per machine, so analyses take turns.
        async with _RUN_LOCK:
            # With the lock held nothing of ours is running, so a sandbox that is open now is one
            # WebSentinel did not start (very likely the user's own, with their work in it) or a
            # leftover from a crash. It is checked here, inside the lock, because outside it a second
            # analysis would see the first one's VM and mistake it for a stray. And it is never
            # closed: a leftover finishes and shuts itself down within moments, so wait briefly for
            # that, then say what is in the way.
            if await asyncio.to_thread(self.vm_is_running):
                if not await asyncio.to_thread(self._wait_until_gone, _FOREIGN_SANDBOX_WAIT_SECONDS):
                    return unavailable_result(
                        "Another Windows Sandbox is already open, so this analysis could not use "
                        "one (only one can run at a time). WebSentinel does not close a sandbox it "
                        "did not start, because it may be yours. Close it and analyse again. If none "
                        "is open, a leftover one can be cleared with an elevated "
                        "'Restart-Service vmcompute -Force'.",
                        self.describe())
            return await asyncio.to_thread(
                self._run_blocking, ext_path, timeout_seconds)

    # ── the blocking half, kept off the event loop ────────────────
    def _run_blocking(self, ext_path: str, timeout_seconds: int) -> Dict[str, Any]:
        report = self.describe()
        staging = _new_staging_dir()
        stage_in = os.path.join(staging, "in")
        stage_out = os.path.join(staging, "out")
        started = time.time()
        launched_at = started
        never_started = False
        closed_early = False
        guest_silent = False
        launched = False

        try:
            os.makedirs(stage_in, exist_ok=True)
            os.makedirs(stage_out, exist_ok=True)

            # Stage the extension and the guest-side code. Only these reach
            # the VM — never the repository or the datasets.
            shutil.copytree(ext_path, os.path.join(stage_in, "extension"))
            # With the shipped runtime the agent and the observation code are already inside
            # c1-guest.exe. Without it (a checkout) they are staged as source for the host's Python.
            bundle = _guest_bundle()
            if not bundle:
                here = os.path.dirname(os.path.abspath(__file__))
                shutil.copy2(os.path.join(here, "guest_agent.py"),
                             os.path.join(stage_in, "guest_agent.py"))
                shutil.copy2(os.path.join(os.path.dirname(here), "sandbox.py"),
                             os.path.join(stage_in, "sandbox_observer.py"))

            with open(os.path.join(stage_in, "bootstrap.cmd"), "w",
                      encoding="ascii", newline="") as handle:
                handle.write(build_bootstrap_cmd(timeout_seconds, bundled=bool(bundle)))

            wsb_path = os.path.join(staging, "run.wsb")
            with open(wsb_path, "w", encoding="utf-8") as handle:
                handle.write(build_wsb_config(
                    staging_in=stage_in,
                    staging_out=stage_out,
                    python_home="" if bundle else _python_home(),
                    site_packages="" if bundle else _site_packages(),
                    guest_bundle=bundle,
                    browsers=_browsers_dir(),
                    networking=(self.network_policy != NET_DISABLED),
                    memory_mb=self.memory_mb,
                ))

            # WindowsSandbox.exe returns as soon as the VM is requested, so the
            # host waits on the guest's own completion marker instead.
            launched_at = time.time()
            subprocess.Popen([_WSB_EXE, wsb_path], close_fds=True)
            launched = True

            deadline = started + timeout_seconds + _BOOT_ALLOWANCE_SECONDS
            marker = os.path.join(stage_out, "done")
            agent_log = os.path.join(stage_out, "agent.log")
            vm_seen = anything_seen = False
            gone_since = 0.0
            next_probe = launched_at + _VM_PROBE_INTERVAL_SECONDS
            while time.time() < deadline and not os.path.exists(marker):
                time.sleep(_POLL_INTERVAL_SECONDS)
                if time.time() < next_probe:
                    continue
                next_probe = time.time() + _VM_PROBE_INTERVAL_SECONDS
                waited = time.time() - launched_at
                vm_now, any_now = self._sandbox_state()
                anything_seen = anything_seen or any_now
                if vm_now:
                    vm_seen, gone_since = True, 0.0
                elif vm_seen:
                    gone_since = gone_since or time.time()
                    if time.time() - gone_since >= _VM_GONE_ALLOWANCE_SECONDS:
                        closed_early = True
                        break
                if not anything_seen and waited > _VM_START_ALLOWANCE_SECONDS:
                    never_started = True
                    break
                if waited > _GUEST_START_ALLOWANCE_SECONDS and not os.path.exists(agent_log):
                    guest_silent = True
                    break

            timed_out = not os.path.exists(marker)
            result = self._read_result(stage_out)

            if result is None:
                if never_started:
                    detail = ("Windows Sandbox did not start: no virtual machine appeared within "
                              f"{_VM_START_ALLOWANCE_SECONDS}s. Check that virtualization is turned "
                              "on in the BIOS and that Windows has restarted since Windows Sandbox "
                              "was turned on")
                elif closed_early:
                    detail = ("Windows Sandbox closed before the analysis finished. It was closed, or "
                              "it stopped on its own; if an error window appeared, its text says why")
                elif guest_silent:
                    detail = ("Windows Sandbox started but the analysis never began inside it (no sign "
                              f"of the guest after {_GUEST_START_ALLOWANCE_SECONDS}s). If an error window "
                              "appeared, its text says why")
                elif timed_out:
                    detail = ("Windows Sandbox timed out before the guest reported a "
                              f"result (waited {int(time.time() - started)}s)")
                else:
                    detail = "Windows Sandbox finished but produced no readable result"
                result = unavailable_result(detail, report)
                result["guest_log"] = self._read_log(stage_out)
                if launched:
                    self._close_windows()          # an error window must not be left on the user's screen

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
                                 text=True, errors="replace",
                                 creationflags=_NO_WINDOW).stdout.lower()
        except (OSError, subprocess.SubprocessError):
            return set()
        return {img for img in _WSB_ALL_IMAGES if img.lower() in out}

    @classmethod
    def vm_is_running(cls) -> bool:
        """True while the sandbox VM itself is still resident."""
        return _WSB_VM_IMAGE in cls._running_images()

    @classmethod
    def _wait_until_gone(cls, seconds: float) -> bool:
        """Wait for the sandbox VM to go away on its own. Closes nothing."""
        deadline = time.time() + seconds
        while cls.vm_is_running():
            if time.time() >= deadline:
                return False
            time.sleep(1.0)
        return True

    @classmethod
    def _sandbox_state(cls) -> Tuple[bool, bool]:
        """From one look at the process list: (the VM is running, the VM or at least its broker is)."""
        images = cls._running_images()
        vm = _WSB_VM_IMAGE in images
        return vm, vm or _WSB_BROKER_IMAGE in images

    @staticmethod
    def _close_windows() -> None:
        """Close the sandbox's own windows, such as an error window left on screen after a failed start.

        Only used after a run that produced no result, and only on a sandbox this analysis launched (the
        run lock is held and a sandbox that was already open is never touched). The VM and its broker
        are left to Windows."""
        for image in _WSB_UI_IMAGES:
            try:
                subprocess.run(["taskkill", "/IM", image, "/F", "/T"],
                               capture_output=True, timeout=30, check=False,
                               creationflags=_NO_WINDOW)
            except (OSError, subprocess.SubprocessError):
                pass

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
                               capture_output=True, timeout=30, check=False,
                               creationflags=_NO_WINDOW)
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
        print(f"[C1-WSB] Could not remove staging directory {staging}. "
              f"It will need deleting manually.")
