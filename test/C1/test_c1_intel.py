"""
C1 Unit Tests — Extension profile, request attribution and network intelligence
Run from project root:  python test/C1/test_c1_intel.py

Covers the evidence the analyzer adds beside the verdict:
  core/c1/profile.py   static profile (what the extension is set up to do)
  core/c1/sandbox.py   request attribution, behaviour counts, summary shape
  core/c1/netintel.py  domain roles, IP addresses, defanged indicators
No browser, no network: lookups are switched off or replaced.
"""
import asyncio
import json
import os
import sys
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

os.environ["C1_NETINTEL_LOOKUPS"] = "off"       # tests never touch DNS

from core.c1 import netintel, profile as prof, sandbox
from core.c1.report import build_report


# ── Fixtures ──────────────────────────────────────────────────────────────────
# A small stand-in for a minified content blocker: registers its content scripts
# from code, schedules two alarms (one named by a constant in an imported file),
# phones a vendor server and sets an uninstall page.
CONFIG_JS = 'const W="https://vendor.example.net";const T="aUpdate";const REG="https://vendor.example.net/register/";'
WORKER_JS = (
    'importScripts("config.js");'
    'chrome["scripting"]["registerContentScripts"]([{js:["main.js"],id:"aa",world:"MAIN",'
    'matches:["<all_urls>"],runAt:"document_start"}]);'
    'chrome["alarms"]["create"](T,{delayInMinutes:60,periodInMinutes:60});'
    'chrome.alarms.create("sendStats",{periodInMinutes:240,delayInMinutes:240});'
    'fetch(REG,{method:"POST",body:"{}"});'
    'chrome.runtime.setUninstallURL("https://vendor.example.net/unregister/?id=1");'
    'var docs="https://www.w3.org/TR/xhtml1/ and http://203.0.113.9/panel";'
)
MANIFEST = {
    "manifest_version": 3, "name": "Blocker", "version": "1.0",
    "background": {"service_worker": "worker.js"},
    "permissions": ["storage", "alarms", "scripting"], "host_permissions": ["<all_urls>"],
    "update_url": "https://clients2.google.com/service/update2/crx",
    "web_accessible_resources": [{"resources": ["a.png"], "matches": ["https://*/*"]}],
    "declarative_net_request": {"rule_resources": [{"id": "r", "enabled": True, "path": "rules.json"}]},
}


def _write_package(root: str) -> None:
    with open(os.path.join(root, "worker.js"), "w", encoding="utf-8") as h:
        h.write(WORKER_JS)
    with open(os.path.join(root, "config.js"), "w", encoding="utf-8") as h:
        h.write(CONFIG_JS)
    rules = ([{"action": {"type": "block"}}] * 5 + [{"action": {"type": "redirect"}}] * 2
             + [{"action": {"type": "modifyHeaders"}}])
    with open(os.path.join(root, "rules.json"), "w", encoding="utf-8") as h:
        json.dump(rules, h)
    with open(os.path.join(root, "helper.exe"), "wb") as h:
        h.write(b"MZ")


def _run(coro):
    return asyncio.run(coro)


# ── Static profile ────────────────────────────────────────────────────────────
class TestProfile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        _write_package(cls._tmp.name)
        cls.full = prof.build_profile(MANIFEST, "", cls._tmp.name)
        cls.lite = prof.build_profile(MANIFEST, CONFIG_JS + "\n" + WORKER_JS, "")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_manifest_facts(self):
        self.assertEqual(self.full["manifest"]["manifest_version"], 3)
        self.assertEqual(self.full["manifest"]["update_source"], "store")
        self.assertEqual(self.full["background"]["kind"], "service_worker")
        self.assertEqual(self.full["site_access"]["scope"], "all_sites")

    def test_runtime_content_scripts_are_found_when_the_manifest_declares_none(self):
        cs = self.full["content_scripts"]
        self.assertEqual(cs["declared"], [])
        self.assertTrue(cs["runtime"]["registered_in_code"])
        self.assertIn("MAIN", cs["runtime"]["worlds"])
        self.assertTrue(cs["runtime"]["all_sites"])
        self.assertTrue(any("from code" in n for n in self.full["notes"]))

    def test_alarms_literal_and_constant_names(self):
        by_name = {a["name"]: a for a in self.full["alarms"]}
        self.assertEqual(by_name["sendStats"]["period_minutes"], 240.0)
        # "T" is defined in an imported file; the name must come back, not the letter
        self.assertEqual(by_name["aUpdate"]["period_minutes"], 60.0)

    def test_unresolvable_alarm_name_is_labelled_not_guessed(self):
        text = 'chrome.alarms.create(zz,{periodInMinutes:5});'
        out = prof.build_profile({"manifest_version": 3}, text, "")
        self.assertEqual(out["alarms"][0]["name"], "(variable zz)")

    def test_unresolved_dotted_alarm_name_keeps_its_last_part(self):
        text = 'chrome.alarms.create(r.SyncUpSensitiveRulesAlarm,{periodInMinutes:5});'
        out = prof.build_profile({"manifest_version": 3}, text, "")
        self.assertEqual(out["alarms"][0]["name"], "(variable SyncUpSensitiveRulesAlarm)")

    def test_template_literals_and_framework_docs_do_not_become_endpoints(self):
        text = ('var a=`https://api.vendor-example.com/${id}/x`;'
                'warn("see https://v3-migration.vuejs.org/breaking-changes/");'
                'fetch("https://api.vendor-example.com/rest/v1");')
        out = prof.build_profile({"manifest_version": 3}, text, "")
        hosts = {e["host"]: e for e in out["endpoints"]}
        self.assertNotIn("v3-migration.vuejs.org", hosts)
        self.assertIn("api.vendor-example.com", hosts)
        for sample in hosts["api.vendor-example.com"]["samples"]:
            self.assertNotIn("$", sample)
            self.assertNotIn("{", sample)

    def test_endpoints_drop_documentation_links_and_keep_real_ones(self):
        hosts = {e["host"]: e for e in self.full["endpoints"]}
        self.assertIn("vendor.example.net", hosts)
        self.assertNotIn("www.w3.org", hosts)
        self.assertTrue(hosts["203.0.113.9"]["ip_literal"])
        self.assertTrue(hosts["203.0.113.9"]["cleartext"])
        self.assertTrue(any("hard-coded IP" in n for n in self.full["notes"]))

    def test_uninstall_url_is_reported_with_a_hint(self):
        self.assertTrue(self.full["uninstall"]["set"])
        self.assertIn("unregister", self.full["uninstall"]["hint"])

    def test_api_usage_counts_bracket_and_dot_access_alike(self):
        browser = self.full["api_usage"]["browser"]
        self.assertGreaterEqual(browser["scripting"], 1)
        self.assertGreaterEqual(browser["alarms"], 2)

    def test_network_rules_and_package_need_the_folder(self):
        self.assertEqual(self.full["network_rules"]["total"], 8)
        self.assertEqual(self.full["network_rules"]["by_action"]["redirect"], 2)
        self.assertIn("helper.exe", self.full["package"]["binaries"])
        self.assertNotIn("network_rules", self.lite)
        self.assertNotIn("package", self.lite)

    def test_web_accessible_resources_open_to_sites(self):
        self.assertTrue(self.full["web_accessible"]["any_site"])

    def test_profile_never_raises(self):
        for bad in (None, [], "x", {"background": "oops", "content_scripts": "no", "permissions": 5}):
            out = prof.build_profile(bad, None, "/does/not/exist")
            self.assertIsInstance(out, dict)
            self.assertIn("notes", out)

    def test_profile_is_json_serialisable_and_compact(self):
        self.assertLess(len(json.dumps(self.full)), 20000)


# ── Request attribution and the sandbox summary ──────────────────────────────
def _req(url, method="GET", source="background", **extra):
    return dict({"url": url, "method": method, "resource_type": "fetch", "source": source, "phase": "bait"}, **extra)


class TestAttribution(unittest.TestCase):
    def test_a_real_sites_post_is_not_scored(self):
        site = [_req("https://news.example.org/collect", "POST", "browse_page", has_body=True, body_size=900)]
        score, flags = sandbox._score(site, [])
        self.assertEqual((score, flags), (0, []))

    def test_the_same_post_from_the_background_worker_is_scored(self):
        mine = [_req("https://vendor.example.net/x", "POST", "background", has_body=True, body_size=900)]
        score, flags = sandbox._score(mine, [])
        self.assertEqual(flags, ["DATA_POST_TO_EXTERNAL"])
        self.assertEqual(score, 20)

    def test_old_shaped_requests_without_a_source_still_count(self):
        legacy = [{"url": "https://vendor.example.net/x", "method": "POST", "resource_type": "fetch"}]
        self.assertEqual(sandbox._score(legacy, [])[1], ["DATA_POST_TO_EXTERNAL"])

    def test_summary_separates_the_extensions_traffic_from_the_sites(self):
        result = {
            "network_requests": [
                _req("https://vendor.example.net/register/", "POST", "background", has_body=True,
                     body_size=58, body_keys=["version", "crx"]),
                _req("https://vendor.example.net/update/?inst_id=1", "GET", "background"),
                _req("https://vendor.example.net/update/?inst_id=1", "GET", "background"),
                _req("https://cdn.news.example.org/a.js", "GET", "browse_page"),
                _req("https://cdn.news.example.org/b.js", "GET", "browse_page"),
                _req("chrome-extension://abc/icon.png", "GET", "background"),
            ],
            "page_signals": [], "background_signals": [], "content_script_signals": [],
            "opened_tabs": ["https://vendor.example.net/installed/"],
            "counters": {"dom_mutations": 24, "console_errors": 1},
        }
        s = sandbox.summarise_observations(result)
        self.assertEqual([h["host"] for h in s["hosts"]], ["vendor.example.net"])
        self.assertEqual(s["hosts"][0]["sources"], ["background"])
        self.assertEqual(s["counts"]["attributed"], 3)
        self.assertEqual(s["counts"]["page_requests"], 2)
        self.assertEqual(s["page_hosts"], [{"host": "cdn.news.example.org", "requests": 2}])
        # one row per distinct call, data-carrying calls first, repeats counted
        self.assertEqual(s["requests"][0]["method"], "POST")
        self.assertEqual(s["requests"][0]["body_keys"], ["version", "crx"])
        self.assertEqual(s["requests"][1]["count"], 2)
        self.assertEqual(s["opened_tabs"], ["https://vendor.example.net/installed/"])
        self.assertEqual(s["behaviour"]["dom_mutations"], 24)

    def test_behaviour_counts_only_scored_signals_and_keeps_eval_previews(self):
        result = {
            "network_requests": [],
            "page_signals": [{"t": "eval", "len": 9, "preview": "var a = 1"}, {"t": "cookie_write"}],
            "background_signals": [{"t": "fetch", "url": "https://x.example/", "src": "background"}],
            "content_script_signals": [{"t": "cookie_read"}, {"t": "key_listener"}],
        }
        b = sandbox.summarise_observations(result)["behaviour"]
        self.assertEqual((b["eval_calls"], b["cookie_reads"], b["key_listeners"]), (1, 1, 1))
        self.assertEqual(b["eval_samples"], ["var a = 1"])
        self.assertEqual(b["calls_by_realm"]["background"], 1)
        self.assertNotIn("cookie_writes", b)          # the bait page writes its own cookies

    def test_summary_of_nothing_is_safe(self):
        for bad in (None, {}, {"network_requests": [None, "x", {}]}):
            self.assertIn("hosts", sandbox.summarise_observations(bad))

    def test_summary_stays_small_for_a_noisy_extension(self):
        noisy = {"network_requests": [_req(f"https://h{i}.example/p{i}", "GET", "background") for i in range(500)]}
        s = sandbox.summarise_observations(noisy)
        self.assertLessEqual(len(s["requests"]), 60)
        self.assertTrue(s["requests_truncated"])
        self.assertLess(len(json.dumps(s)), 40000)


class TestGuestStaysSelfContained(unittest.TestCase):
    def test_sandbox_module_has_no_package_imports_at_load_time(self):
        # isolation/guest_agent.py copies sandbox.py alone into the VM as
        # sandbox_observer.py, so importing a sibling module there would fail.
        import ast
        with open(sandbox.__file__, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        relative = [n.module for n in tree.body if isinstance(n, ast.ImportFrom) and n.level > 0]
        self.assertEqual(relative, [])


class TestDisplayName(unittest.TestCase):
    def test_translation_key_is_resolved_from_the_locales_folder(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "_locales", "en"))
            with open(os.path.join(root, "_locales", "en", "messages.json"), "w", encoding="utf-8") as h:
                json.dump({"Title": {"message": "Ad Blocker Pro"}}, h)
            manifest = {"name": "__MSG_title__", "default_locale": "en"}
            self.assertEqual(sandbox._display_name(manifest, root), "Ad Blocker Pro")
            self.assertEqual(sandbox._display_name({"name": "Plain"}, root), "Plain")
            self.assertEqual(sandbox._display_name({"name": "__MSG_missing__"}, root), "")


# ── Network intelligence ─────────────────────────────────────────────────────
class TestNetworkIntel(unittest.TestCase):
    OBSERVED = {
        "hosts": [{"host": "vendor.example.net", "requests": 5, "methods": ["POST", "GET"], "sources": ["background"]},
                  {"host": "fonts.gstatic.com", "requests": 1, "methods": ["GET"], "sources": []}],
        "requests": [{"url": "https://vendor.example.net/register/?inst_id=SECRET"},
                     {"url": "https://vendor.example.net/update/"}],
        "opened_tabs": ["https://vendor.example.net/installed/"],
    }
    PROFILE = {"endpoints": [{"host": "vendor.example.net"}, {"host": "www.youtube.com"},
                             {"host": "203.0.113.9", "ip_literal": True}]}

    def test_defanging(self):
        self.assertEqual(netintel.defang_host("a.b.com"), "a[.]b[.]com")
        self.assertEqual(netintel.defang_url("https://a.com/p/q.js?id=SECRET"), "hxxps[://]a[.]com/p/q.js")
        self.assertEqual(netintel.defang_url("http://1.2.3.4/x"), "hxxp[://]1[.]2[.]3[.]4/x")

    def test_host_kinds(self):
        declared = {"vendor.example.net"}
        self.assertEqual(netintel._kind("api.vendor.example.net", declared), "declared")
        self.assertEqual(netintel._kind("fonts.gstatic.com", declared), "known_service")
        self.assertEqual(netintel._kind("203.0.113.9", declared), "ip_literal")
        self.assertEqual(netintel._kind("odd-host.xyz", declared), "unexplained")

    def test_domain_table_roles_and_indicators(self):
        out = _run(netintel.build_network_intel(self.OBSERVED, self.PROFILE))
        roles = {d["host"]: (d["role"], d["kind"]) for d in out["domains"]}
        self.assertEqual(roles["vendor.example.net"], ("contacted", "declared"))
        self.assertEqual(roles["fonts.gstatic.com"], ("contacted", "known_service"))
        self.assertEqual(roles["www.youtube.com"], ("declared", "known_service"))
        iocs = out["iocs"]
        self.assertIn("vendor[.]example[.]net", iocs["domains"])
        self.assertNotIn("www[.]youtube[.]com", iocs["domains"])       # mentioned, never contacted
        self.assertEqual(iocs["urls"][0], "hxxps[://]vendor[.]example[.]net/register/")   # query dropped
        self.assertNotIn("SECRET", json.dumps(iocs))
        self.assertEqual(out["lookups"], {"dns": "off"})

    def test_ip_literal_endpoints_become_ip_indicators(self):
        out = _run(netintel.build_network_intel(self.OBSERVED, self.PROFILE))
        self.assertIn("203[.]0[.]113[.]9", out["iocs"]["ips"])

    def test_no_sandbox_run_still_lists_declared_endpoints(self):
        out = _run(netintel.build_network_intel(None, self.PROFILE))
        self.assertTrue(out["domains"])
        self.assertTrue(all(d["role"] == "declared" for d in out["domains"]))

    def test_dns_lookup_fills_in_ip_addresses(self):
        real_env = os.environ.pop("C1_NETINTEL_LOOKUPS")
        real_resolve = netintel._resolve

        async def fake_resolve(host):
            return ["198.51.100.7"] if host == "vendor.example.net" else []

        try:
            netintel._resolve = fake_resolve
            out = _run(netintel.build_network_intel(self.OBSERVED, self.PROFILE))
        finally:
            os.environ["C1_NETINTEL_LOOKUPS"] = real_env
            netintel._resolve = real_resolve
        vendor = next(d for d in out["domains"] if d["host"] == "vendor.example.net")
        self.assertEqual(vendor["ips"], ["198.51.100.7"])
        self.assertIn("198.51.100.7", out["ips"])
        self.assertEqual(out["lookups"], {"dns": "ok"})

    def test_no_third_party_reputation_service_is_contacted(self):
        # The servers table carries role, kind and addresses only; nothing here
        # calls out to a reputation service or reads an API key.
        import inspect
        source = inspect.getsource(netintel).lower()
        self.assertNotIn("virustotal", source)
        out = _run(netintel.build_network_intel(self.OBSERVED, self.PROFILE))
        self.assertTrue(all("vt" not in d for d in out["domains"]))

    def test_garbage_in_never_raises(self):
        for obs, pro in ((None, None), ("x", 5), ({"hosts": [None, 3]}, {"endpoints": "no"})):
            out = _run(netintel.build_network_intel(obs, pro))
            self.assertIn("iocs", out)


# ── The report carries the evidence ──────────────────────────────────────────
class TestReportCarriesEvidence(unittest.TestCase):
    def test_profile_and_network_intel_ride_inside_the_report(self):
        result = {"verdict": "SAFE", "score": 0.1, "static": {}, "dynamic": {}, "flags": [],
                  "profile": {"notes": ["x"]}, "network_intel": {"domains": []}}
        rep = build_report(result)
        self.assertEqual(rep["profile"], {"notes": ["x"]})
        self.assertEqual(rep["network_intel"], {"domains": []})

    def test_older_results_without_the_blocks_still_build(self):
        rep = build_report({"verdict": "SAFE", "score": 0.1, "static": {}, "dynamic": {}, "flags": []})
        self.assertEqual(rep["profile"], {})
        self.assertEqual(rep["network_intel"], {})

    def test_summary_mentions_a_page_the_extension_opened(self):
        dyn = {"executed": True, "observed": {"counts": {"hosts": 1}, "hosts": [{"sources": ["background"]}],
                                               "opened_tabs": ["https://vendor.example.net/installed/"]}}
        rep = build_report({"verdict": "SUSPICIOUS", "score": 0.5, "static": {}, "dynamic": dyn, "flags": []})
        self.assertIn("opened a web page on its own", rep["plain_summary"])
        self.assertIn("vendor.example.net", rep["plain_summary"])


class TestUnpackedFolderFallback(unittest.TestCase):
    def test_static_pass_reuses_the_folder_the_intercept_already_unpacked(self):
        from unittest import mock
        from core.c1 import analyzer
        with tempfile.TemporaryDirectory() as home:
            ext_id = "a" * 32
            folder = os.path.join(home, ".websentinel", "extensions", ext_id)
            os.makedirs(folder)
            with mock.patch("os.path.expanduser", return_value=home):
                self.assertEqual(analyzer._unpacked_folder("", ext_id), folder)
                self.assertEqual(analyzer._unpacked_folder("/given/path", ext_id), "/given/path")
                self.assertEqual(analyzer._unpacked_folder("", "b" * 32), "")
                self.assertEqual(analyzer._unpacked_folder("", ""), "")


class TestEvidenceSurvivesHistory(unittest.TestCase):
    """A stored analysis is rebuilt from its report JSON alone, so the new
    evidence has to be inside the report to still be there when it is reopened."""

    def test_profile_and_network_intel_survive_a_save_and_reload(self):
        from core.c1 import db
        original = db._DB_PATH
        db._DB_PATH = os.path.join(tempfile.mkdtemp(prefix="c1_intel_rt_"), "t.db")
        try:
            result = {
                "score": 0.5, "verdict": "SUSPICIOUS", "detail": "d", "flags": [], "extension_id": "abc",
                "timestamp": "2026-10-10T10:00:00", "source": "upload",
                "static": {"score": 0.5, "ml_score": 0.5, "hash_match": False, "anomaly_score": 0.1},
                "dynamic": {"score": 0.2, "executed": True, "signals": [], "observed": {
                    "hosts": [], "counts": {}, "requests": [{"method": "POST", "url": "https://v.example/r", "source": "background",
                                                              "count": 1, "has_body": True, "body_size": 58, "body_keys": ["version"]}]}},
                "profile": prof.build_profile(MANIFEST, WORKER_JS + CONFIG_JS, ""),
                "network_intel": {"domains": [{"host": "v.example", "role": "contacted", "kind": "declared"}],
                                  "iocs": {"domains": ["v[.]example"], "ips": [], "urls": []}},
            }
            result["report"] = build_report(result)
            db.save_result(result)
            row = db.get_history(1)[0]
        finally:
            db._DB_PATH = original
        self.assertTrue(any(a["name"] == "sendStats" for a in row["report"]["profile"]["alarms"]))
        self.assertEqual(row["report"]["network_intel"]["iocs"]["domains"], ["v[.]example"])
        self.assertEqual(row["report"]["observed"]["requests"][0]["body_keys"], ["version"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
