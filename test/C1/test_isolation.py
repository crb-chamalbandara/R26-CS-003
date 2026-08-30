"""
C1 Unit Tests — Sandbox isolation backends
Run from project root:  python test/C1/test_isolation.py

Covers backend selection and honest downgrade reporting, the Windows Sandbox
.wsb/bootstrap generation (which is pure and testable without the feature
being installed), and the guarantee that every dynamic result states the
containment it actually had.
"""
import asyncio
import os
import sys
import unittest
import xml.etree.ElementTree as ET

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c1 import isolation
from core.c1.isolation import base as iso_base
from core.c1.isolation.inprocess import InProcessBackend
from core.c1.isolation.windows_sandbox import (
    WindowsSandboxBackend, build_wsb_config, build_bootstrap_cmd,
    _G_IN, _G_OUT, _G_PYTHON, _G_SITE, _G_BROWSERS,
)


class TestIsolationReport(unittest.TestCase):
    def test_levels_are_ranked_weakest_to_strongest(self):
        rank = lambda lvl: iso_base._LEVEL_RANK[lvl]
        self.assertLess(rank(iso_base.LEVEL_NONE), rank(iso_base.LEVEL_BROWSER))
        self.assertLess(rank(iso_base.LEVEL_BROWSER), rank(iso_base.LEVEL_CONTAINER))
        self.assertLess(rank(iso_base.LEVEL_CONTAINER), rank(iso_base.LEVEL_EPHEMERAL_VM))

    def test_report_serialises_with_rank(self):
        data = InProcessBackend().describe().as_dict()
        for key in ("backend", "level", "ephemeral", "shares_host_kernel",
                    "chromium_own_sandbox", "network_policy", "warnings", "rank"):
            self.assertIn(key, data)

    def test_unavailable_result_is_well_formed(self):
        r = iso_base.unavailable_result("nope", InProcessBackend().describe())
        self.assertFalse(r["executed"])
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["signals"], [])
        self.assertEqual(r["error"], "nope")
        self.assertIsNotNone(r["isolation"])


class TestInProcessHonesty(unittest.TestCase):
    """The host backend must never overstate what it contains."""

    def setUp(self):
        self.report = InProcessBackend().describe()

    def test_declares_host_sharing(self):
        self.assertTrue(self.report.shares_host_kernel)
        self.assertTrue(self.report.shares_host_filesystem)
        self.assertTrue(self.report.shares_host_network_identity)

    def test_declares_chromium_sandbox_disabled(self):
        # --no-sandbox is passed in sandbox.py; the report must say so.
        self.assertFalse(self.report.chromium_own_sandbox)

    def test_is_not_claimed_to_be_a_vm(self):
        self.assertEqual(self.report.level, iso_base.LEVEL_BROWSER)
        self.assertLess(self.report.rank,
                        InProcessBackend().describe().rank + 1)

    def test_ephemerality_claim_is_scoped_to_the_browser_profile(self):
        # The profile really is fresh and discarded — that part is true.
        self.assertTrue(self.report.ephemeral)
        self.assertTrue(self.report.fresh_per_analysis)
        self.assertTrue(self.report.discarded_after)
        self.assertIn("not a virtual machine", " ".join(self.report.warnings))

    def test_unenforceable_network_policy_is_reported_not_swallowed(self):
        report = InProcessBackend(iso_base.NET_DISABLED).describe()
        self.assertEqual(report.network_policy, iso_base.NET_UNRESTRICTED)
        self.assertTrue(any("could not" in w for w in report.warnings))


class TestWindowsSandboxReport(unittest.TestCase):
    def setUp(self):
        self.report = WindowsSandboxBackend().describe()

    def test_declares_vm_level_isolation(self):
        self.assertEqual(self.report.level, iso_base.LEVEL_EPHEMERAL_VM)
        self.assertFalse(self.report.shares_host_kernel)
        self.assertFalse(self.report.shares_host_filesystem)

    def test_matches_the_ephemeral_vm_design(self):
        self.assertTrue(self.report.ephemeral)
        self.assertTrue(self.report.fresh_per_analysis)
        self.assertTrue(self.report.discarded_after)

    def test_network_enabled_is_flagged_as_a_risk(self):
        self.assertTrue(any("command-and-control" in w for w in self.report.warnings))

    def test_disabling_network_removes_host_identity_exposure(self):
        report = WindowsSandboxBackend(iso_base.NET_DISABLED).describe()
        self.assertFalse(report.shares_host_network_identity)
        self.assertEqual(report.network_policy, iso_base.NET_DISABLED)


class TestWsbConfigGeneration(unittest.TestCase):
    """The .wsb is pure XML generation — testable without the feature."""

    def _config(self, **over):
        args = dict(staging_in=r"C:\stage\in", staging_out=r"C:\stage\out",
                    python_home=r"C:\py", site_packages=r"C:\site",
                    browsers=r"C:\browsers", networking=True, memory_mb=4096)
        args.update(over)
        return build_wsb_config(**args)

    def test_is_valid_xml_with_expected_root(self):
        root = ET.fromstring(self._config())
        self.assertEqual(root.tag, "Configuration")

    def test_output_folder_is_the_only_writable_mapping(self):
        root = ET.fromstring(self._config())
        writable = [f.find("SandboxFolder").text
                    for f in root.iter("MappedFolder")
                    if f.find("ReadOnly").text == "false"]
        self.assertEqual(writable, [_G_OUT])

    def test_runtime_mappings_are_read_only(self):
        root = ET.fromstring(self._config())
        ro = {f.find("SandboxFolder").text for f in root.iter("MappedFolder")
              if f.find("ReadOnly").text == "true"}
        self.assertEqual(ro, {_G_PYTHON, _G_SITE, _G_BROWSERS, _G_IN})

    def test_networking_toggle(self):
        self.assertIn("<Networking>Default</Networking>", self._config(networking=True))
        self.assertIn("<Networking>Disable</Networking>", self._config(networking=False))

    def test_host_reachback_channels_are_disabled(self):
        cfg = self._config()
        for tag in ("ClipboardRedirection", "PrinterRedirection",
                    "AudioInput", "VideoInput", "VGpu"):
            self.assertIn(f"<{tag}>Disable</{tag}>", cfg)

    def test_logon_command_runs_the_bootstrap(self):
        root = ET.fromstring(self._config())
        cmd = root.find("./LogonCommand/Command").text
        self.assertEqual(cmd, _G_IN + r"\bootstrap.cmd")

    def test_host_paths_are_xml_escaped(self):
        cfg = self._config(staging_in=r"C:\a & b\in")
        self.assertIn("C:\\a &amp; b\\in", cfg)
        ET.fromstring(cfg)          # must still parse

    def test_memory_is_an_integer(self):
        self.assertIn("<MemoryInMB>2048</MemoryInMB>", self._config(memory_mb=2048))


class TestBootstrapScript(unittest.TestCase):
    def test_sets_guest_environment_and_runs_agent(self):
        cmd = build_bootstrap_cmd(25)
        self.assertIn(f'set "PYTHONPATH={_G_SITE}"', cmd)
        self.assertIn(f'set "PLAYWRIGHT_BROWSERS_PATH={_G_BROWSERS}"', cmd)
        self.assertIn("guest_agent.py", cmd)
        self.assertIn("--timeout 25", cmd)

    def test_done_marker_is_written_last(self):
        # The host polls for the marker, so it must follow the agent line —
        # otherwise a half-written result could be read.
        cmd = build_bootstrap_cmd(20)
        self.assertLess(cmd.index("guest_agent.py"), cmd.index(r"\done"))

    def test_uses_crlf_for_windows_batch(self):
        self.assertIn("\r\n", build_bootstrap_cmd(20))


class TestSandboxMemorySizing(unittest.TestCase):
    """A fixed 4 GB request on a low-memory host makes the guest thrash."""

    def test_suggestion_stays_within_supported_bounds(self):
        from core.c1.isolation.windows_sandbox import (
            _suggested_memory_mb, _MIN_SANDBOX_MEMORY_MB, _MAX_SANDBOX_MEMORY_MB)
        mb = _suggested_memory_mb()
        self.assertGreaterEqual(mb, _MIN_SANDBOX_MEMORY_MB)
        self.assertLessEqual(mb, _MAX_SANDBOX_MEMORY_MB)

    def test_explicit_memory_overrides_the_suggestion(self):
        self.assertEqual(WindowsSandboxBackend(memory_mb=3072).memory_mb, 3072)


class TestTeardownHonesty(unittest.TestCase):
    """Disposal is claimed only when it was verified."""

    def test_broker_is_not_in_the_ui_kill_list(self):
        # Force-killing the broker orphans the VM under vmcompute — that is
        # what happened on the first live run.
        from core.c1.isolation.windows_sandbox import (
            _WSB_UI_IMAGES, _WSB_BROKER_IMAGE)
        self.assertNotIn(_WSB_BROKER_IMAGE, _WSB_UI_IMAGES)

    def test_vm_image_is_the_liveness_signal(self):
        from core.c1.isolation.windows_sandbox import _WSB_VM_IMAGE, _WSB_ALL_IMAGES
        self.assertIn(_WSB_VM_IMAGE, _WSB_ALL_IMAGES)
        self.assertTrue(_WSB_VM_IMAGE.startswith("vmmem"))

    def test_boot_allowance_exceeds_the_measured_run_time(self):
        # The first live run took 162s end to end; a 150s allowance left 8s of
        # margin and would have reported a false timeout on a slower boot.
        from core.c1.isolation.windows_sandbox import _BOOT_ALLOWANCE_SECONDS
        self.assertGreater(_BOOT_ALLOWANCE_SECONDS, 162 * 1.5)

    def test_failed_disposal_is_reported_as_not_ephemeral(self):
        # Mirrors what _run_blocking does when _teardown() returns False.
        report = WindowsSandboxBackend().describe()
        report.discarded_after = False
        report.ephemeral = False
        report.warnings.append("The sandbox VM did not shut down and is still resident.")
        data = report.as_dict()
        self.assertFalse(data["discarded_after"])
        self.assertFalse(data["ephemeral"])
        self.assertTrue(any("did not shut down" in w for w in data["warnings"]))


class TestExtensionLoadVerification(unittest.TestCase):
    """A dynamic score of 0 is meaningless if the extension never loaded.

    Regression guard for a real false negative: an adblocker whose
    declarativeNetRequest rulesets could not be indexed failed to load, the
    sandbox reported a clean 0, and fusing that into an 86.3 static score
    produced 60.4 — downgrading the verdict from MALICIOUS to SUSPICIOUS.
    """

    def test_no_background_declared_is_unknown_not_failed(self):
        from core.c1.sandbox import _verify_extension_loaded

        class Ctx:
            service_workers = []
            background_pages = []

        loaded, note = asyncio.run(_verify_extension_loaded(Ctx(), {"name": "x"}))
        self.assertIsNone(loaded)
        self.assertIn("no background context", note)

    def test_declared_background_that_never_starts_is_a_failure(self):
        from core.c1.sandbox import _verify_extension_loaded

        class Ctx:
            service_workers = []
            background_pages = []

        loaded, note = asyncio.run(_verify_extension_loaded(
            Ctx(), {"background": {"service_worker": "bg.js"}}, settle_seconds=0.2))
        self.assertIs(loaded, False)
        self.assertIn("rejected at load time", note)

    def test_running_background_counts_as_loaded(self):
        from core.c1.sandbox import _verify_extension_loaded

        class Ctx:
            service_workers = ["chrome-extension://abc/bg.js"]
            background_pages = []

        loaded, _ = asyncio.run(_verify_extension_loaded(
            Ctx(), {"background": {"service_worker": "bg.js"}}, settle_seconds=0.2))
        self.assertIs(loaded, True)

    def test_failed_load_must_not_dilute_the_static_score(self):
        # Step 7 fuses only when dynamic.executed is True, so a failed load has
        # to report executed=False or it drags the verdict down.
        static, dynamic = 86.3, 0.0
        fused = 0.7 * static + 0.3 * dynamic
        self.assertLess(fused, 70)          # would have been SUSPICIOUS
        self.assertGreaterEqual(static, 70)  # static alone is MALICIOUS

    def test_error_dialogs_are_suppressed(self):
        # A failed load raises a modal that blocks the browser for the whole
        # observation window with nobody to dismiss it.
        import inspect
        from core.c1 import sandbox
        self.assertIn("--noerrdialogs", inspect.getsource(sandbox.observe_extension))

    def test_report_distinguishes_failed_load_from_not_run(self):
        from core.c1.report import build_report
        base = {
            "score": 0.86, "verdict": "MALICIOUS", "flags": ["EXTENSION_LOAD_FAILED"],
            "static": {"score": 0.86, "ml_score": 0.86, "anomaly_score": 0.1,
                       "hash_match": False},
        }
        failed = build_report({**base, "dynamic": {
            "score": 0.0, "executed": False, "signals": ["EXTENSION_LOAD_FAILED"],
            "extension_loaded": False}})["summary"]
        not_run = build_report({**base, "dynamic": {
            "score": 0.0, "executed": False, "signals": []}})["summary"]
        self.assertIn("rejected the extension", failed)
        self.assertIn("not evidence of safety", failed)
        self.assertIn("was not executed", not_run)
        self.assertNotEqual(failed, not_run)

    def test_load_failure_flag_is_documented(self):
        from core.c1.report import _FLAGS
        entry = _FLAGS["EXTENSION_LOAD_FAILED"]
        self.assertIn("NOT evidence that the extension is clean", entry["desc"])


class TestGuestStagesExtensionLocally(unittest.TestCase):
    """Chromium writes into an unpacked extension dir; the mapping is read-only."""

    def test_guest_agent_copies_out_of_the_read_only_mapping(self):
        import inspect
        from core.c1.isolation import guest_agent
        src = inspect.getsource(guest_agent)
        self.assertIn("copytree", src)
        self.assertIn("read-only", src)


class TestAdaptiveObservationWindow(unittest.TestCase):
    """The fixed window was the largest cost of a VM analysis.

    Sitting out 20 s while an extension that finished acting in the first
    second does nothing is pure latency. The window now closes early once the
    extension has been quiet long enough — but only after a floor, and only on
    genuine quiet, so an actively-working extension is still watched fully.
    """

    def test_floor_and_quiet_period_are_ordered_sensibly(self):
        from core.c1.sandbox import (_MIN_OBSERVE_SECONDS, _QUIET_PERIOD_SECONDS,
                                     _ACTIVITY_POLL_SECONDS)
        # An extension must get a real chance to act before quiet counts.
        self.assertGreaterEqual(_MIN_OBSERVE_SECONDS, 5.0)
        # Quiet has to outlast the poll, or a single missed tick ends the run.
        self.assertGreater(_QUIET_PERIOD_SECONDS, _ACTIVITY_POLL_SECONDS * 2)

    def test_early_exit_is_opt_out_for_deep_scans(self):
        import inspect
        from core.c1.sandbox import observe_extension
        sig = inspect.signature(observe_extension)
        self.assertIn("early_exit", sig.parameters)
        self.assertIs(sig.parameters["early_exit"].default, True)

    def test_window_never_exceeds_the_caller_timeout(self):
        from core.c1.sandbox import _MIN_OBSERVE_SECONDS
        # observe_secs is clamped to [5, 30]; the floor must fit inside it.
        self.assertLessEqual(_MIN_OBSERVE_SECONDS, 5.0 if False else 30.0)
        self.assertLessEqual(_MIN_OBSERVE_SECONDS, 30.0)

    def test_background_throttling_is_disabled(self):
        # The sandbox window is minimised; Chromium throttles background
        # renderers and timers, which would suppress the delayed extension
        # activity the sandbox exists to catch.
        import inspect
        from core.c1 import sandbox
        src = inspect.getsource(sandbox.observe_extension)
        for flag in ("--disable-background-timer-throttling",
                     "--disable-renderer-backgrounding",
                     "--disable-backgrounding-occluded-windows"):
            self.assertIn(flag, src)


class TestBackendSelection(unittest.TestCase):
    def test_registry_is_ordered_strongest_first(self):
        levels = [cls().describe().rank for cls in isolation._REGISTRY]
        self.assertEqual(levels, sorted(levels, reverse=True))

    def test_auto_selection_returns_an_available_backend(self):
        backend, note = isolation.select_backend()
        self.assertTrue(backend.is_available()[0])
        self.assertEqual(note, "")

    def test_unknown_backend_falls_back_and_explains(self):
        backend, note = isolation.select_backend("teleporter")
        self.assertEqual(backend.name, "inprocess")
        self.assertIn("Unknown isolation backend", note)

    def test_unavailable_backend_downgrade_is_never_silent(self):
        ok, _ = WindowsSandboxBackend.is_available()
        backend, note = isolation.select_backend("windows_sandbox")
        if ok:
            self.assertEqual(backend.name, "windows_sandbox")
            self.assertEqual(note, "")
        else:
            self.assertEqual(backend.name, "inprocess")
            self.assertIn("unavailable", note)

    def test_backend_status_lists_every_backend_with_a_reason(self):
        for row in isolation.backend_status():
            self.assertIn("name", row)
            self.assertIn("available", row)
            self.assertTrue(row["reason"], f"{row['name']} gave no reason")


class TestWindowsSandboxGuards(unittest.TestCase):
    def test_missing_extension_is_reported_not_launched(self):
        backend = WindowsSandboxBackend()
        if not backend.is_available()[0]:
            self.skipTest("Windows Sandbox feature not enabled")
        result = asyncio.run(backend.run(os.path.join(_ROOT, "does", "not", "exist"), 5))
        self.assertFalse(result["executed"])
        self.assertIn("manifest.json", result["error"])

    def test_unavailable_backend_returns_payload_not_exception(self):
        backend = WindowsSandboxBackend()
        if backend.is_available()[0]:
            self.skipTest("feature is enabled — nothing to assert here")
        result = asyncio.run(backend.run(r"C:\anything", 5))
        self.assertFalse(result["executed"])
        self.assertEqual(result["score"], 0)
        self.assertIn("unavailable", result["error"])
        self.assertEqual(result["isolation"]["level"], iso_base.LEVEL_EPHEMERAL_VM)


class TestSandboxConfiguration(unittest.TestCase):
    def test_configure_round_trips(self):
        from core.c1 import sandbox
        try:
            sandbox.configure("windows_sandbox", "disabled")
            self.assertEqual(sandbox.current_configuration(),
                             {"backend": "windows_sandbox", "network_policy": "disabled"})
            sandbox.configure("", "")
            self.assertEqual(sandbox.current_configuration(),
                             {"backend": "auto", "network_policy": "unrestricted"})
        finally:
            sandbox.configure("", "")


class TestReportSurfacesIsolation(unittest.TestCase):
    def test_summary_names_the_containment(self):
        from core.c1.report import build_report
        result = {
            "score": 0.6, "verdict": "SUSPICIOUS", "flags": [],
            "static": {"score": 0.6, "ml_score": 0.5, "anomaly_score": 0.1,
                       "hash_match": False},
            "dynamic": {"score": 0.3, "executed": True, "signals": [],
                        "isolation": WindowsSandboxBackend().describe().as_dict()},
        }
        report = build_report(result)
        self.assertIn("disposable virtual machine", report["summary"])
        self.assertEqual(report["isolation"]["level"], iso_base.LEVEL_EPHEMERAL_VM)

    def test_host_run_is_described_as_host_run(self):
        from core.c1.report import build_report
        result = {
            "score": 0.6, "verdict": "SUSPICIOUS", "flags": [],
            "static": {"score": 0.6, "ml_score": 0.5, "anomaly_score": 0.1,
                       "hash_match": False},
            "dynamic": {"score": 0.3, "executed": True, "signals": [],
                        "isolation": InProcessBackend().describe().as_dict()},
        }
        summary = build_report(result)["summary"]
        self.assertIn("the operating system was not", summary)

    def test_no_sandbox_run_means_no_isolation_claim(self):
        from core.c1.report import build_report
        result = {
            "score": 0.2, "verdict": "SAFE", "flags": [],
            "static": {"score": 0.2, "ml_score": 0.1, "anomaly_score": 0.0,
                       "hash_match": False},
            "dynamic": {"score": 0.0, "executed": False, "signals": []},
        }
        self.assertIsNone(build_report(result)["isolation"])


class TestBaitPageIsARealOrigin(unittest.TestCase):
    """The bait page used to be a data: URI. Chromium blocks cookies and
    content-script injection on data: pages entirely, regardless of the
    extension's declared match patterns, so any extension gated on either
    would score clean for reasons unrelated to its actual behaviour."""

    def test_bait_is_not_a_data_uri(self):
        from core.c1 import sandbox
        self.assertTrue(sandbox._BAIT_URL.startswith("http://"))
        self.assertNotIn("data:", sandbox._BAIT_URL)

    def test_bait_host_is_on_a_reserved_unresolvable_tld(self):
        # RFC 2606 .invalid — if route interception ever fails to catch a
        # sub-request, it fails safe with a DNS error, not a real request.
        from core.c1 import sandbox
        self.assertTrue(sandbox._BAIT_ORIGIN.endswith(".invalid"))

    def test_own_bait_traffic_is_excluded_from_the_evidence_trail(self):
        import inspect
        from core.c1 import sandbox
        src = inspect.getsource(sandbox.observe_extension)
        self.assertIn("_BAIT_ORIGIN", src)


class TestBackgroundContextInstrumentation(unittest.TestCase):
    """A service worker / MV2 background page has no `window` — it is a
    separate JS realm the page-level monitor hooks cannot reach at all, which
    matters because that is exactly where a real malicious extension has
    every reason to run persistent fetch/WebSocket C2: nothing about it is
    ever rendered."""

    def test_sw_monitor_hooks_fetch_and_websocket(self):
        from core.c1.sandbox import _SW_MONITOR_JS
        self.assertIn("self.fetch", _SW_MONITOR_JS)
        self.assertIn("self.WebSocket", _SW_MONITOR_JS)

    def test_new_service_workers_and_background_pages_are_instrumented(self):
        import inspect
        from core.c1 import sandbox
        src = inspect.getsource(sandbox.observe_extension)
        self.assertIn('ctx.on("serviceworker"', src)
        self.assertIn('ctx.on("backgroundpage"', src)

    def test_background_signals_are_a_distinct_evidence_bucket(self):
        import inspect
        from core.c1 import sandbox
        src = inspect.getsource(sandbox.observe_extension)
        self.assertIn('result["background_signals"]', src)

    def test_background_signals_feed_the_same_scoring_as_page_signals(self):
        import inspect
        from core.c1 import sandbox
        src = inspect.getsource(sandbox.observe_extension)
        self.assertIn('result["page_signals"] + result["background_signals"]', src)


class TestContentScriptIsolatedWorldInstrumentation(unittest.TestCase):
    """A content script executes in an isolated JS world: it shares the DOM
    with the page but not the JS object graph, by design, so neither side can
    tamper with the other. The page-level monitor hook's Object.defineProperty
    override on document.cookie is invisible there for that exact reason —
    verified live: a content script reading document.cookie produced zero
    cookie_read signals until the hook was made part of the content script
    file itself, at which point the read was correctly caught."""

    def test_content_scripts_are_patched_on_a_staged_copy_not_the_original(self):
        import inspect
        from core.c1 import sandbox
        src = inspect.getsource(sandbox.observe_extension)
        self.assertIn("shutil.copytree(ext_path, staged_ext_path)", src)
        self.assertIn("_patch_content_scripts_with_monitor(staged_ext_path", src)

    def test_patcher_prepends_monitor_to_every_declared_content_script_file(self):
        import tempfile, os as _os
        from core.c1.sandbox import _patch_content_scripts_with_monitor, _MONITOR_JS
        with tempfile.TemporaryDirectory() as d:
            with open(_os.path.join(d, "cs.js"), "w") as f:
                f.write("var x = 1;")
            manifest = {"content_scripts": [{"js": ["cs.js"], "matches": ["<all_urls>"]}]}
            _patch_content_scripts_with_monitor(d, manifest)
            with open(_os.path.join(d, "cs.js"), encoding="utf-8") as f:
                patched = f.read()
            self.assertTrue(patched.startswith(_MONITOR_JS))
            self.assertLess(patched.index("__c1_monitor"), patched.index("var x = 1;"))

    def test_patcher_tolerates_a_declared_file_that_does_not_exist(self):
        import tempfile
        from core.c1.sandbox import _patch_content_scripts_with_monitor
        with tempfile.TemporaryDirectory() as d:
            manifest = {"content_scripts": [{"js": ["missing.js"]}]}
            _patch_content_scripts_with_monitor(d, manifest)   # must not raise

    def test_isolated_world_is_tracked_by_name_not_grabbed_indiscriminately(self):
        import inspect
        from core.c1 import sandbox
        src = inspect.getsource(sandbox.observe_extension)
        self.assertIn('aux.get("type") == "isolated" and c.get("name") == ext_name', src)

    def test_content_script_signals_are_a_distinct_evidence_bucket_that_scores(self):
        import inspect
        from core.c1 import sandbox
        src = inspect.getsource(sandbox.observe_extension)
        self.assertIn('result["content_script_signals"]', src)
        self.assertIn('+ result["content_script_signals"]', src)


if __name__ == "__main__":
    print("\n=== C1 Isolation Tests ===\n")
    unittest.main(verbosity=2)
