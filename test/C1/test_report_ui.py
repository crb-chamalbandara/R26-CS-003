"""
C1 Unit Tests — Report surface data contract
Run from project root:  python test/C1/test_report_ui.py

Covers the backend half of the Simple/Advanced report: the permission risk
catalogue, the sandbox observation rollup, the plain-language summary, and —
most importantly — that all three survive a round trip through SQLite. History
entries are rebuilt entirely from the stored report JSON, so anything that
lives outside it is present on a live analysis and silently gone the moment the
user reopens the same analysis from the history list.
"""
import json
import os
import sys
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c1.permissions import explain_permissions, permission_risk_counts
from core.c1.sandbox import summarise_observations
from core.c1.report import build_report, _plain_summary


class TestPermissionCatalogue(unittest.TestCase):

    def test_blanket_host_access_is_critical(self):
        for pattern in ("<all_urls>", "*://*/*", "https://*/*"):
            entries = explain_permissions({"host_permissions": [pattern]})
            self.assertEqual(entries[0]["severity"], "CRITICAL", pattern)
            self.assertTrue(entries[0]["is_host"])

    def test_named_origin_is_not_treated_as_blanket(self):
        entries = explain_permissions({"host_permissions": ["https://*.bugsnag.com/*"]})
        self.assertEqual(entries[0]["severity"], "MEDIUM")
        self.assertIn("bugsnag.com", entries[0]["description"])

    def test_mv2_host_patterns_inside_permissions_are_found(self):
        # MV2 has no host_permissions field at all — match patterns sit in the
        # main permissions array. Missing this reads an MV2 extension with full
        # host access as if it had none.
        entries = explain_permissions({"permissions": ["tabs", "<all_urls>"]})
        by_name = {e["name"]: e for e in entries}
        self.assertTrue(by_name["<all_urls>"]["is_host"])
        self.assertEqual(by_name["<all_urls>"]["severity"], "CRITICAL")

    def test_unknown_permission_is_kept_not_dropped(self):
        entries = explain_permissions({"permissions": ["someFuturePermission"]})
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["severity"], "LOW")
        self.assertIn("not", entries[0]["description"].lower())

    def test_entries_are_sorted_most_severe_first(self):
        entries = explain_permissions(
            {"permissions": ["storage", "cookies", "tabs", "nativeMessaging"]})
        order = [e["severity"] for e in entries]
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.assertEqual(order, sorted(order, key=lambda s: rank[s]))

    def test_duplicates_are_collapsed(self):
        entries = explain_permissions({"permissions": ["tabs", "tabs", "Tabs"]})
        self.assertEqual(len(entries), 1)

    def test_risk_counts_drive_the_stat_card(self):
        entries = explain_permissions(
            {"permissions": ["cookies", "webRequest", "storage"]})
        counts = permission_risk_counts(entries)
        self.assertEqual(counts["total"], 3)
        self.assertEqual(counts["high_risk"], counts["CRITICAL"] + counts["HIGH"])
        self.assertGreaterEqual(counts["high_risk"], 2)

    def test_malformed_manifest_does_not_raise(self):
        for bad in (None, [], "string", {"permissions": None},
                    {"permissions": [None, 5, {}]}):
            explain_permissions(bad)      # must not raise


class TestObservationSummary(unittest.TestCase):

    def _result(self, net=None, page=None, bg=None, cs=None):
        return {"network_requests": net or [], "page_signals": page or [],
                "background_signals": bg or [], "content_script_signals": cs or []}

    def test_browser_internal_urls_are_excluded(self):
        s = summarise_observations(self._result(net=[
            {"url": "chrome-extension://abc/bg.js", "method": "GET"},
            {"url": "https://real.example.com/x", "method": "GET"},
        ]))
        self.assertEqual([h["host"] for h in s["hosts"]], ["real.example.com"])

    def test_realm_attribution_is_preserved(self):
        s = summarise_observations(self._result(
            bg=[{"t": "fetch", "url": "https://c2.example.com/a", "src": "background"}],
            cs=[{"t": "fetch", "url": "https://ads.example.com/b", "src": "content_script"}],
        ))
        by = {h["host"]: h for h in s["hosts"]}
        self.assertEqual(by["c2.example.com"]["sources"], ["background"])
        self.assertEqual(by["ads.example.com"]["sources"], ["content_script"])

    def test_raw_ip_and_websocket_are_flagged(self):
        s = summarise_observations(self._result(
            net=[{"url": "http://127.0.0.1:9/beacon", "method": "GET"}],
            bg=[{"t": "ws", "url": "wss://c2.example.com/s", "src": "background"}],
        ))
        by = {h["host"]: h for h in s["hosts"]}
        self.assertTrue(by["127.0.0.1:9"]["suspicious"])
        self.assertTrue(by["c2.example.com"]["suspicious"])

    def test_host_list_is_capped_and_says_so(self):
        # A real extension can contact hundreds of hosts; the whole list would
        # be persisted into every stored report.
        net = [{"url": f"https://h{i}.example.com/x", "method": "GET"}
               for i in range(120)]
        s = summarise_observations(self._result(net=net))
        self.assertEqual(len(s["hosts"]), 40)
        self.assertTrue(s["truncated"])
        self.assertEqual(s["counts"]["hosts"], 120)

    def test_busiest_hosts_survive_the_cap(self):
        net = [{"url": f"https://h{i}.example.com/x", "method": "GET"}
               for i in range(60)]
        net += [{"url": "https://busy.example.com/x", "method": "POST"}] * 25
        s = summarise_observations(self._result(net=net))
        self.assertEqual(s["hosts"][0]["host"], "busy.example.com")
        self.assertEqual(s["hosts"][0]["requests"], 25)

    def test_counts_split_by_realm(self):
        s = summarise_observations(self._result(
            page=[{"t": "cookie_read"}], bg=[{"t": "eval"}, {"t": "eval"}],
            cs=[{"t": "key_listener"}]))
        c = s["counts"]
        self.assertEqual((c["page"], c["background"], c["content_script"]), (1, 2, 1))
        self.assertEqual(c["signals"], 4)

    def test_empty_and_malformed_input_is_safe(self):
        for bad in ({}, None, {"network_requests": None}):
            out = summarise_observations(bad)
            self.assertEqual(out["hosts"], [])


class TestPlainSummary(unittest.TestCase):

    def test_opens_with_the_verdict_in_plain_words(self):
        for verdict, expect in (("MALICIOUS", "should not be installed"),
                                ("SAFE", "Nothing harmful")):
            text = _plain_summary(verdict, 50, [], [], {"executed": False})
            self.assertIn(expect, text)

    def test_never_claims_clean_behaviour_when_nothing_was_watched(self):
        # The trap this whole design guards against: silence from a sandbox
        # that never ran must not read as a clean bill of health.
        text = _plain_summary("SAFE", 10, [], [], {"executed": False})
        self.assertIn("not tested", text)
        self.assertNotIn("contacted no external servers", text)

    def test_load_failure_is_stated_as_not_a_clean_result(self):
        text = _plain_summary("MALICIOUS", 86, [], [],
                              {"executed": False, "extension_loaded": False})
        self.assertIn("not the same as it being safe", text)

    def test_names_background_traffic_when_present(self):
        dyn = {"executed": True, "observed": {
            "counts": {"hosts": 2},
            "hosts": [{"host": "a.com", "sources": ["background"]},
                      {"host": "b.com", "sources": ["page"]}]}}
        text = _plain_summary("MALICIOUS", 90, [], [], dyn)
        self.assertIn("background process", text)

    def test_mentions_the_worst_permission(self):
        perms = [{"name": "<all_urls>", "severity": "CRITICAL",
                  "description": "Can read and change your data on every website you visit."}]
        text = _plain_summary("MALICIOUS", 90, [], perms, {"executed": False})
        self.assertIn("every website you visit", text)


class TestReportCarriesTheNewFields(unittest.TestCase):

    def _result(self):
        return {
            "score": 0.9, "verdict": "MALICIOUS", "flags": ["COOKIE_EXFILTRATION_RISK"],
            "static": {"score": 0.9, "ml_score": 0.8, "anomaly_score": 0.2,
                       "hash_match": False},
            "dynamic": {"score": 0.5, "executed": True, "signals": [],
                        "observed": {"hosts": [{"host": "x.com", "requests": 2,
                                                "methods": ["GET"], "sources": ["background"],
                                                "suspicious": False}],
                                     "counts": {"requests": 2, "hosts": 1, "signals": 3},
                                     "truncated": False}},
            "identity": {"name": "Demo", "version": "1.0", "ext_id": "abc",
                         "provenance": "manifest"},
            "permissions": [{"name": "cookies", "severity": "CRITICAL",
                             "description": "Can read the login tokens…", "is_host": False}],
        }

    def test_report_exposes_identity_permissions_observed_and_plain_summary(self):
        rpt = build_report(self._result())
        for key in ("identity", "permissions", "observed", "plain_summary"):
            self.assertIn(key, rpt, key)
        self.assertEqual(rpt["identity"]["name"], "Demo")
        self.assertEqual(len(rpt["permissions"]), 1)
        self.assertEqual(rpt["observed"]["counts"]["hosts"], 1)
        self.assertTrue(rpt["plain_summary"])

    def test_missing_extras_degrade_to_empty_not_crash(self):
        bare = {"score": 0.1, "verdict": "SAFE", "flags": [],
                "static": {}, "dynamic": {}}
        rpt = build_report(bare)
        self.assertEqual(rpt["permissions"], [])
        self.assertEqual(rpt["identity"], {})
        self.assertTrue(rpt["plain_summary"])


class TestHistoryRoundTrip(unittest.TestCase):
    """The regression this design is most exposed to.

    A history row is reconstructed from the stored report JSON alone. If the
    new panels are not restored there, the report looks complete on a fresh
    analysis and quietly loses its permissions, identity and network view the
    moment the same analysis is reopened.
    """

    def setUp(self):
        from core.c1 import db
        self.db = db
        self._orig = db._DB_PATH
        db._DB_PATH = os.path.join(tempfile.mkdtemp(prefix="c1_rt_"), "t.db")

    def tearDown(self):
        self.db._DB_PATH = self._orig

    def _save_and_reload(self):
        result = {
            "score": 0.9, "verdict": "MALICIOUS", "detail": "d",
            "flags": ["COOKIE_EXFILTRATION_RISK"], "extension_id": "abc",
            "timestamp": "2026-08-30T10:00:00", "source": "upload",
            "static": {"score": 0.9, "ml_score": 0.8, "hash_match": False,
                       "anomaly_score": 0.2},
            "dynamic": {"score": 0.5, "executed": True, "signals": [],
                        "observed": {"hosts": [{"host": "c2.example.com", "requests": 7,
                                                "methods": ["POST"], "sources": ["background"],
                                                "suspicious": True}],
                                     "counts": {"requests": 7, "hosts": 1, "signals": 4},
                                     "truncated": False}},
            "identity": {"name": "Demo Ext", "version": "2.1", "ext_id": "abc",
                         "provenance": "manifest"},
            "permissions": [{"name": "cookies", "severity": "CRITICAL",
                             "description": "Reads login tokens.", "is_host": False},
                            {"name": "storage", "severity": "LOW",
                             "description": "Saves settings.", "is_host": False}],
        }
        result["report"] = build_report(result)
        self.db.save_result(result)
        return self.db.get_history(1)[0]

    def test_identity_survives(self):
        self.assertEqual(self._save_and_reload()["identity"]["name"], "Demo Ext")

    def test_permissions_survive(self):
        perms = self._save_and_reload()["permissions"]
        self.assertEqual(len(perms), 2)
        self.assertEqual(perms[0]["severity"], "CRITICAL")

    def test_observed_network_survives(self):
        obs = self._save_and_reload()["dynamic"]["observed"]
        self.assertEqual(obs["counts"]["hosts"], 1)
        self.assertEqual(obs["hosts"][0]["host"], "c2.example.com")
        self.assertEqual(obs["hosts"][0]["sources"], ["background"])
        self.assertTrue(obs["hosts"][0]["suspicious"])

    def test_plain_summary_survives(self):
        self.assertTrue(self._save_and_reload()["report"]["plain_summary"])

    def test_stored_report_stays_small_enough_to_persist(self):
        # The cap exists so a noisy extension cannot bloat every stored row.
        net = [{"url": f"https://h{i}.example.com/x", "method": "GET"}
               for i in range(400)]
        obs = summarise_observations({"network_requests": net, "page_signals": [],
                                      "background_signals": [], "content_script_signals": []})
        self.assertLess(len(json.dumps(obs)), 12000)


if __name__ == "__main__":
    print("\n=== C1 Report Surface Tests ===\n")
    unittest.main(verbosity=2)
