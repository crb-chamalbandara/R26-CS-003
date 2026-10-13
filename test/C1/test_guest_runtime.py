"""
C1 Unit Tests - the VM's runtime in an installed build, and knowing early when a VM cannot start
Run from project root:  python test/C1/test_guest_runtime.py

Covers what changed so the disposable-VM analysis works from an installed WebSentinel:

  * the installed backend is a frozen program with no python.exe or site-packages to lend the VM, so the
    installer ships c1_guest\\c1-guest.exe and the .wsb and bootstrap use it instead;
  * the backend finds that folder next to itself, and says so plainly when it is missing;
  * a PC that cannot start a VM (virtualization off in the BIOS, or no restart since Windows Sandbox was
    turned on) is told so at once, and a sandbox that never starts is abandoned after a short allowance
    instead of after several minutes.

Everything here is pure or uses fakes: no VM is started and no Windows feature is touched.
"""
import os
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c1.isolation import windows_sandbox as w
from core.c1.isolation.windows_sandbox import (
    WindowsSandboxBackend, build_wsb_config, build_bootstrap_cmd,
    _G_GUEST, _G_IN, _G_OUT, _G_PYTHON, _G_SITE, _G_BROWSERS, _GUEST_EXE_NAME,
)


def _touch(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb"):
        pass
    return path


class TestWsbWithTheShippedRuntime(unittest.TestCase):

    def _config(self, **over):
        args = dict(staging_in=r"C:\stage\in", staging_out=r"C:\stage\out", browsers=r"C:\browsers",
                    guest_bundle=r"C:\app\resources\c1_guest", networking=True, memory_mb=4096)
        args.update(over)
        return build_wsb_config(**args)

    def test_is_valid_xml(self):
        self.assertEqual(ET.fromstring(self._config()).tag, "Configuration")

    def test_the_runtime_is_the_bundle_not_the_hosts_python(self):
        root = ET.fromstring(self._config())
        guest = {f.find("SandboxFolder").text: f.find("HostFolder").text for f in root.iter("MappedFolder")}
        self.assertEqual(guest[_G_GUEST], r"C:\app\resources\c1_guest")
        self.assertNotIn(_G_PYTHON, guest)
        self.assertNotIn(_G_SITE, guest)

    def test_only_the_output_folder_is_writable(self):
        root = ET.fromstring(self._config())
        writable = [f.find("SandboxFolder").text for f in root.iter("MappedFolder") if f.find("ReadOnly").text == "false"]
        self.assertEqual(writable, [_G_OUT])

    def test_everything_else_mapped_is_read_only(self):
        root = ET.fromstring(self._config())
        ro = {f.find("SandboxFolder").text for f in root.iter("MappedFolder") if f.find("ReadOnly").text == "true"}
        self.assertEqual(ro, {_G_GUEST, _G_BROWSERS, _G_IN})

    def test_no_host_python_is_needed_to_build_it(self):
        # python_home and site_packages are simply not given
        ET.fromstring(self._config())

    def test_a_checkout_still_gets_the_hosts_python(self):
        cfg = build_wsb_config(staging_in=r"C:\i", staging_out=r"C:\o", python_home=r"C:\py", site_packages=r"C:\site",
                               browsers=r"C:\b", networking=True, memory_mb=2048)
        self.assertIn(_G_PYTHON, cfg)
        self.assertNotIn(_G_GUEST, cfg)


class TestBootstrapWithTheShippedRuntime(unittest.TestCase):

    def test_runs_the_shipped_program(self):
        cmd = build_bootstrap_cmd(25, bundled=True)
        self.assertIn(_G_GUEST + "\\" + _GUEST_EXE_NAME, cmd)
        self.assertIn("--timeout 25", cmd)
        self.assertIn(f'set "PLAYWRIGHT_BROWSERS_PATH={_G_BROWSERS}"', cmd)

    def test_does_not_use_a_python_or_a_staged_script(self):
        cmd = build_bootstrap_cmd(25, bundled=True)
        self.assertNotIn("python.exe", cmd)
        self.assertNotIn("guest_agent.py", cmd)
        self.assertNotIn("PYTHONPATH", cmd)

    def test_the_done_marker_still_comes_last(self):
        cmd = build_bootstrap_cmd(20, bundled=True)
        self.assertLess(cmd.index(_GUEST_EXE_NAME), cmd.index(r"\done"))
        self.assertLess(cmd.index(r"\done"), cmd.index("shutdown"))

    def test_the_default_is_unchanged_for_a_checkout(self):
        cmd = build_bootstrap_cmd(25)
        self.assertIn("python.exe", cmd)
        self.assertIn("guest_agent.py", cmd)
        self.assertIn(f'set "PYTHONPATH={_G_SITE}"', cmd)


class TestFindingTheRuntime(unittest.TestCase):
    """The installed layout is <install>\\resources\\backend\\websentinel-backend.exe next to <install>\\resources\\c1_guest."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="c1_rt_")
        self.addCleanup(self.tmp.cleanup)
        self.resources = os.path.join(self.tmp.name, "resources")
        self.exe = _touch(os.path.join(self.resources, "backend", "websentinel-backend.exe"))
        self.bundle = os.path.join(self.resources, "c1_guest")
        self.env = mock.patch.dict(os.environ, {"C1_GUEST_DIR": ""})
        self.env.start()
        self.addCleanup(self.env.stop)

    def _frozen(self):
        stack = mock.patch.object(sys, "frozen", True, create=True)
        stack.start()
        self.addCleanup(stack.stop)
        exe = mock.patch.object(sys, "executable", self.exe)
        exe.start()
        self.addCleanup(exe.stop)

    def test_found_next_to_the_installed_backend(self):
        _touch(os.path.join(self.bundle, _GUEST_EXE_NAME))
        self._frozen()
        self.assertEqual(w._guest_bundle(), self.bundle)

    def test_an_installed_build_with_the_runtime_needs_no_python(self):
        _touch(os.path.join(self.bundle, _GUEST_EXE_NAME))
        browsers = os.path.join(self.tmp.name, "ms-playwright", "chromium-1")
        os.makedirs(browsers)
        self._frozen()
        with mock.patch.object(w, "_browsers_dir", return_value=os.path.dirname(browsers)):
            self.assertEqual(w._missing_dependencies(), [])

    def test_an_installed_build_without_it_says_so_and_never_asks_for_python(self):
        self._frozen()
        with mock.patch.object(w, "_browsers_dir", return_value=self.tmp.name):
            missing = " ".join(w._missing_dependencies())
        self.assertIn("guest runtime", missing)
        self.assertNotIn("python.exe", missing)
        self.assertIn("Reinstalling", missing)

    def test_an_override_names_a_runtime_for_a_checkout(self):
        _touch(os.path.join(self.bundle, _GUEST_EXE_NAME))
        with mock.patch.dict(os.environ, {"C1_GUEST_DIR": self.bundle}):
            self.assertEqual(w._guest_bundle(), self.bundle)

    def test_a_wrong_override_is_reported_not_ignored(self):
        with mock.patch.dict(os.environ, {"C1_GUEST_DIR": os.path.join(self.tmp.name, "nope")}):
            self.assertEqual(w._guest_bundle(), "")
            self.assertIn("guest runtime", " ".join(w._missing_dependencies()))

    def test_a_checkout_without_an_override_has_no_bundle(self):
        self.assertEqual(w._guest_bundle(), "")


class TestAvailabilityMessages(unittest.TestCase):

    def test_an_installed_build_with_the_feature_off_says_how_to_turn_it_on(self):
        with mock.patch.object(sys, "frozen", True, create=True), \
             mock.patch.object(w, "_WSB_EXE", os.path.join(tempfile.gettempdir(), "no_such_WindowsSandbox.exe")):
            ok, reason = WindowsSandboxBackend.is_available()
        self.assertFalse(ok)
        self.assertIn("Windows Features", reason)
        self.assertIn("installer", reason)

    def test_a_virtualization_problem_is_the_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            launcher = _touch(os.path.join(tmp, "WindowsSandbox.exe"))
            with mock.patch.object(w, "_WSB_EXE", launcher), \
                 mock.patch.object(w, "_missing_dependencies", return_value=[]), \
                 mock.patch.object(w, "_virtualization_problem", return_value="virtualization is turned off"):
                ok, reason = WindowsSandboxBackend.is_available()
        self.assertEqual((ok, reason), (False, "virtualization is turned off"))

    def test_no_problem_means_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            launcher = _touch(os.path.join(tmp, "WindowsSandbox.exe"))
            with mock.patch.object(w, "_WSB_EXE", launcher), \
                 mock.patch.object(w, "_missing_dependencies", return_value=[]), \
                 mock.patch.object(w, "_virtualization_problem", return_value=""):
                self.assertTrue(WindowsSandboxBackend.is_available()[0])


class TestVirtualizationPreflight(unittest.TestCase):

    def setUp(self):
        w._preflight_cache.update(at=0.0, problem="")
        self.addCleanup(lambda: w._preflight_cache.update(at=0.0, problem=""))

    def _problem(self, hypervisor, firmware=True):
        with mock.patch.object(w, "_hypervisor_running", return_value=hypervisor), \
             mock.patch.object(w, "_firmware_virtualization_on", return_value=firmware):
            return w._virtualization_problem()

    def test_a_running_hypervisor_is_no_problem(self):
        self.assertEqual(self._problem(True), "")

    def test_a_running_hypervisor_is_no_problem_even_when_the_firmware_flag_reads_off(self):
        # measured on a PC where Windows Sandbox works: with the hypervisor running, the firmware flag reads False
        self.assertEqual(self._problem(True, firmware=False), "")

    def test_an_unreadable_state_blames_nothing(self):
        self.assertEqual(self._problem(None, firmware=False), "")

    def test_no_hypervisor_but_virtualization_on_means_restart(self):
        reason = self._problem(False, firmware=True)
        self.assertIn("restart", reason.lower())
        self.assertNotIn("BIOS", reason)

    def test_no_hypervisor_and_virtualization_off_means_bios(self):
        reason = self._problem(False, firmware=False)
        self.assertIn("BIOS", reason)
        self.assertIn("VT-x", reason)

    def test_the_answer_is_cached_briefly(self):
        with mock.patch.object(w, "_hypervisor_running", return_value=True) as ask:
            w._virtualization_problem()
            w._virtualization_problem()
            w._virtualization_problem()
        self.assertEqual(ask.call_count, 1)

    def test_the_answer_is_asked_again_after_the_cache_expires(self):
        with mock.patch.object(w, "_hypervisor_running", return_value=True) as ask:
            w._virtualization_problem()
            w._preflight_cache["at"] -= w._PREFLIGHT_TTL_SECONDS + 1
            w._virtualization_problem()
        self.assertEqual(ask.call_count, 2)


class TestNeverClosingASandboxWeDidNotStart(unittest.TestCase):
    """A sandbox that is open when an analysis starts is probably the user's own. It is never force-closed,
    and the check happens inside the lock, so two analyses cannot mistake each other's VM for a stray."""

    def _extension(self, tmp):
        ext = os.path.join(tmp, "ext")
        os.makedirs(ext)
        with open(os.path.join(ext, "manifest.json"), "w") as handle:
            handle.write("{}")
        return ext

    def test_an_open_sandbox_is_not_closed_and_the_user_is_told(self):
        import asyncio
        with tempfile.TemporaryDirectory() as tmp:
            ext = self._extension(tmp)
            with mock.patch.object(WindowsSandboxBackend, "is_available", return_value=(True, "")), \
                 mock.patch.object(w, "_FOREIGN_SANDBOX_WAIT_SECONDS", 0.2), \
                 mock.patch.object(WindowsSandboxBackend, "vm_is_running", return_value=True), \
                 mock.patch.object(WindowsSandboxBackend, "_teardown") as teardown, \
                 mock.patch.object(w.subprocess, "run") as ran, \
                 mock.patch.object(WindowsSandboxBackend, "_run_blocking") as run_blocking:
                result = asyncio.run(WindowsSandboxBackend(memory_mb=2048).run(ext, 5))
        self.assertFalse(result["executed"])
        self.assertIn("Another Windows Sandbox is already open", result["error"])
        self.assertIn("does not close", result["error"])
        teardown.assert_not_called()                  # nothing was closed
        for call in ran.call_args_list:
            self.assertNotIn("taskkill", " ".join(map(str, call.args[0])))
        run_blocking.assert_not_called()              # and nothing was launched on top of it

    def test_a_leftover_that_finishes_by_itself_lets_the_analysis_proceed(self):
        import asyncio
        with tempfile.TemporaryDirectory() as tmp:
            ext = self._extension(tmp)
            seen = iter([True, True, False, False, False])
            with mock.patch.object(WindowsSandboxBackend, "is_available", return_value=(True, "")), \
                 mock.patch.object(w, "_FOREIGN_SANDBOX_WAIT_SECONDS", 30), \
                 mock.patch.object(w.time, "sleep", lambda *_: None), \
                 mock.patch.object(WindowsSandboxBackend, "vm_is_running", side_effect=lambda: next(seen, False)), \
                 mock.patch.object(WindowsSandboxBackend, "_teardown") as teardown, \
                 mock.patch.object(WindowsSandboxBackend, "_run_blocking", return_value={"executed": True}) as run_blocking:
                result = asyncio.run(WindowsSandboxBackend(memory_mb=2048).run(ext, 5))
        self.assertEqual(result, {"executed": True})
        run_blocking.assert_called_once()
        teardown.assert_not_called()

    def test_two_analyses_take_turns_and_neither_closes_the_others_vm(self):
        import asyncio
        active = {"now": 0, "max": 0}

        def fake_run(self_, ext_path, timeout):
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
            time.sleep(0.3)
            active["now"] -= 1
            return {"executed": True}

        async def both(backend, ext):
            return await asyncio.gather(backend.run(ext, 5), backend.run(ext, 5))

        with tempfile.TemporaryDirectory() as tmp:
            ext = self._extension(tmp)
            with mock.patch.object(WindowsSandboxBackend, "is_available", return_value=(True, "")), \
                 mock.patch.object(WindowsSandboxBackend, "vm_is_running", return_value=False), \
                 mock.patch.object(WindowsSandboxBackend, "_teardown") as teardown, \
                 mock.patch.object(WindowsSandboxBackend, "_run_blocking", fake_run):
                results = asyncio.run(both(WindowsSandboxBackend(memory_mb=2048), ext))
        self.assertEqual([r["executed"] for r in results], [True, True])
        self.assertEqual(active["max"], 1)            # one at a time
        teardown.assert_not_called()                  # run() itself never tears anything down

    def test_waiting_for_a_leftover_closes_nothing(self):
        with mock.patch.object(WindowsSandboxBackend, "vm_is_running", return_value=True), \
             mock.patch.object(w.time, "sleep", lambda *_: None), \
             mock.patch.object(w.subprocess, "run") as ran:
            self.assertFalse(WindowsSandboxBackend._wait_until_gone(0.0))
        ran.assert_not_called()


class TestTheStagingFolderWorksWhenRunningAsAdministrator(unittest.TestCase):
    """The failure this guards against: with WebSentinel running as administrator, the folder shared into
    the VM could only be opened by an elevated process, and Windows Sandbox (normal user rights) failed
    with "Access is denied (0x80070005)". The folder must inherit the temp folder's permissions, which
    name the user, instead of the restricted list tempfile.mkdtemp() writes."""

    def test_it_does_not_use_mkdtemp(self):
        with mock.patch.object(tempfile, "mkdtemp", side_effect=AssertionError("mkdtemp must not be used")):
            path = w._new_staging_dir()
        self.addCleanup(lambda: os.path.isdir(path) and os.rmdir(path))
        self.assertTrue(os.path.isdir(path))

    def test_the_folder_is_named_and_placed_as_before(self):
        path = w._new_staging_dir()
        self.addCleanup(lambda: os.path.isdir(path) and os.rmdir(path))
        self.assertTrue(os.path.basename(path).startswith("c1_wsb_"))
        self.assertEqual(os.path.dirname(path), tempfile.gettempdir())

    def test_each_run_gets_its_own_folder(self):
        paths = {w._new_staging_dir() for _ in range(5)}
        for path in paths:
            self.addCleanup(lambda p=path: os.path.isdir(p) and os.rmdir(p))
        self.assertEqual(len(paths), 5)

    @unittest.skipUnless(sys.platform == "win32", "permissions are a Windows matter")
    def test_it_inherits_the_temp_folders_permissions(self):
        import subprocess
        path = w._new_staging_dir()
        self.addCleanup(lambda: os.path.isdir(path) and os.rmdir(path))
        listing = subprocess.run(["icacls", path], capture_output=True, text=True).stdout
        # an inherited entry is marked (I); a restricted list written by mkdtemp has none
        self.assertIn("(I)", listing, listing)
        self.assertIn(os.environ.get("USERNAME", ""), listing)

    @unittest.skipUnless(sys.platform == "win32", "permissions are a Windows matter")
    def test_subfolders_made_under_it_inherit_as_well(self):
        import subprocess
        path = w._new_staging_dir()
        inner = os.path.join(path, "out")
        os.makedirs(inner)
        self.addCleanup(lambda: (os.path.isdir(inner) and os.rmdir(inner), os.path.isdir(path) and os.rmdir(path)))
        listing = subprocess.run(["icacls", inner], capture_output=True, text=True).stdout
        self.assertIn("(I)", listing, listing)


def _run(tmp, timeout=5, prepare=None, calls=None, **patched):
    """Run one analysis through _run_blocking with the sandbox faked, and return (result, seconds)."""
    ext = os.path.join(tmp, "ext")
    os.makedirs(ext, exist_ok=True)
    with open(os.path.join(ext, "manifest.json"), "w") as handle:
        handle.write("{}")
    bundle = os.path.join(tmp, "c1_guest")
    _touch(os.path.join(bundle, _GUEST_EXE_NAME))
    settings = {"_VM_START_ALLOWANCE_SECONDS": 1, "_VM_PROBE_INTERVAL_SECONDS": 0.1, "_VM_GONE_ALLOWANCE_SECONDS": 0.4,
                "_GUEST_START_ALLOWANCE_SECONDS": 60, "_POLL_INTERVAL_SECONDS": 0.05, "_BOOT_ALLOWANCE_SECONDS": 3}
    states = patched.pop("states")
    recorded = calls if calls is not None else []
    settings.update(patched)
    staging = os.path.join(tmp, "staging")
    os.makedirs(staging, exist_ok=True)
    if prepare:
        prepare(staging)
    patches = [mock.patch.dict(os.environ, {"C1_GUEST_DIR": bundle})]
    patches += [mock.patch.object(w, name, value) for name, value in settings.items()]
    patches += [mock.patch.object(w, "_browsers_dir", return_value=tmp),
                mock.patch.object(w, "_new_staging_dir", return_value=staging),
                mock.patch.object(w, "_NO_WINDOW", 0),
                mock.patch.object(w.subprocess, "Popen"),
                mock.patch.object(w.subprocess, "run", side_effect=lambda cmd, **kw: recorded.append(cmd)),
                mock.patch.object(WindowsSandboxBackend, "_sandbox_state", side_effect=states),
                mock.patch.object(WindowsSandboxBackend, "_remove_staging"),
                mock.patch.object(WindowsSandboxBackend, "_teardown", return_value=True)]
    for p in patches:
        p.start()
    try:
        started = time.time()
        result = WindowsSandboxBackend(memory_mb=2048)._run_blocking(ext, timeout)
        return result, time.time() - started
    finally:
        for p in reversed(patches):
            p.stop()


class _Seq:
    """A sequence of sandbox states, then the last one for ever."""
    def __init__(self, *states):
        self.states, self.i = states, 0

    def __call__(self):
        state = self.states[min(self.i, len(self.states) - 1)]
        self.i += 1
        return state


GONE, BROKER, UP = (False, False), (False, True), (True, True)


class TestFailingFastWhenTheSandboxDoesNotWork(unittest.TestCase):
    """The measured failure: Windows Sandbox shows "Access is denied" and the analysis used to wait for
    the whole allowance (7.6 minutes). The VM appears and vanishes while the broker stays alive."""

    def test_no_sandbox_process_at_all_gives_up_early(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, took = _run(tmp, states=_Seq(GONE))
        self.assertLess(took, 20)
        self.assertIn("did not start", result["error"])
        self.assertIn("virtualization", result["error"])

    def test_a_vm_that_appears_and_vanishes_is_reported_though_the_broker_stays(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, took = _run(tmp, states=_Seq(UP, BROKER), _BOOT_ALLOWANCE_SECONDS=60)
        self.assertLess(took, 20)
        self.assertFalse(result["executed"])
        self.assertIn("closed before the analysis finished", result["error"])

    def test_a_guest_that_never_reports_in_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, took = _run(tmp, states=_Seq(UP), _GUEST_START_ALLOWANCE_SECONDS=0.5, _BOOT_ALLOWANCE_SECONDS=60)
        self.assertLess(took, 20)
        self.assertIn("never began inside it", result["error"])

    def test_a_healthy_run_is_never_cut_short(self):
        # VM up throughout, guest reported in (agent.log exists): only the ordinary deadline can end it
        def guest_started(staging):
            _touch(os.path.join(staging, "out", "agent.log"))
        with tempfile.TemporaryDirectory() as tmp:
            result, took = _run(tmp, timeout=1, states=_Seq(UP), prepare=guest_started, _GUEST_START_ALLOWANCE_SECONDS=0.2,
                                _BOOT_ALLOWANCE_SECONDS=2)
        self.assertIn("timed out", result["error"])
        for wrong in ("did not start", "closed before", "never began"):
            self.assertNotIn(wrong, result["error"])

    def test_the_vm_state_comes_from_one_look_at_the_process_list(self):
        images = lambda *names: mock.patch.object(WindowsSandboxBackend, "_running_images", return_value=set(names))
        with images(w._WSB_VM_IMAGE):
            self.assertEqual(WindowsSandboxBackend._sandbox_state(), (True, True))
        with images(w._WSB_BROKER_IMAGE):
            self.assertEqual(WindowsSandboxBackend._sandbox_state(), (False, True))
        with images("WindowsSandbox.exe"):
            self.assertEqual(WindowsSandboxBackend._sandbox_state(), (False, False))   # a window alone is not a VM
        with images():
            self.assertEqual(WindowsSandboxBackend._sandbox_state(), (False, False))


class TestNoErrorWindowIsLeftBehind(unittest.TestCase):

    def test_a_failed_run_closes_the_sandbox_windows_but_not_the_vm_or_broker(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = []
            _run(tmp, states=_Seq(UP, BROKER), _BOOT_ALLOWANCE_SECONDS=60, calls=calls)
        closed = {c[2] for c in calls if c and c[0] == "taskkill"}
        self.assertEqual(closed, set(w._WSB_UI_IMAGES))
        self.assertNotIn(w._WSB_BROKER_IMAGE, closed)
        self.assertNotIn(w._WSB_VM_IMAGE, closed)

    def test_a_successful_run_closes_nothing(self):
        # a result was reported: Windows ends the sandbox itself
        with tempfile.TemporaryDirectory() as tmp:
            def with_result(staging):
                import json
                os.makedirs(os.path.join(staging, "out"), exist_ok=True)
                with open(os.path.join(staging, "out", "result.json"), "w") as handle:
                    json.dump({"executed": True, "score": 0, "signals": []}, handle)
                _touch(os.path.join(staging, "out", "done"))
            calls = []
            result, _ = _run(tmp, states=_Seq(UP), prepare=with_result, calls=calls)
        self.assertTrue(result["executed"])
        self.assertFalse([c for c in calls if c and c[0] == "taskkill"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
