"""
C1 Unit Tests — Blocklist evidence completion
Run from project root:  python test/C1/test_blocklist_evidence.py

Covers the path that documents an under-reported blocklist row from a live
intercept: placeholder detection, reason derivation, the CSV write-back, and
the analyzer contract for a gapped-vs-documented blocklist hit.
"""
import asyncio
import csv
import json
import os
import shutil
import sys
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c1 import blocklist as bl
from core.c1 import enrich


SHEET_HEADER = ",".join(bl.HEADERS)

# One curated row (full evidence) and one from the ID-only dump (all placeholders)
SHEET_BODY = "\n".join([
    SHEET_HEADER,
    'cigkgjjhaklfppedcelcdnffcnfhmcen,Whatsapp Bulk Messenger,Policy Violation,'
    'MalExt Sentry Database,8/25/2026,Chrome,1,0fe6708337d9b4d4204e83d523d8217d',
    'pnlphjjfielecalmmjjdhjjninkbjdod,Not Found,Not yet confirmed,'
    '"""chrome-mal-ids"" Dataset",N/A,Not Confirmed,Not Confirmed,Not Found',
    '',
])


def write_sheet(directory):
    path = os.path.join(directory, "sheet.csv")
    with open(path, "w", encoding="cp1252", newline="") as handle:
        handle.write(SHEET_BODY)
    return path


# ── Placeholder handling ──────────────────────────────────────────────────────
class TestPlaceholderDetection(unittest.TestCase):
    def test_sheet_placeholders_count_as_missing(self):
        for value in ("Not Found", "not found", "Not Confirmed",
                      "Not yet confirmed", "N/A", "", "  ", "unknown"):
            self.assertTrue(bl.is_missing(value), f"{value!r} should read as missing")

    def test_real_values_are_not_missing(self):
        for value in ("Adware", "Malware", "Chrome", "3.8.8", "8/25/2026",
                      "Removal reason Unknown"):
            self.assertFalse(bl.is_missing(value), f"{value!r} should read as present")

    def test_removal_reason_unknown_is_a_real_reason(self):
        # 263 curated rows use this wording — it is a sourced reason, not a gap.
        self.assertNotIn("removal reason unknown", bl.MISSING_TOKENS)


class TestLoadAndGaps(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="c1_bl_test_")
        self.path = write_sheet(self.dir)
        self.entries = bl.load_blocklist(self.path)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_placeholder_cells_load_as_empty(self):
        entry = self.entries["pnlphjjfielecalmmjjdhjjninkbjdod"]
        self.assertEqual(entry["extension_name"], "")
        self.assertEqual(entry["reason"], "")
        self.assertEqual(entry["date"], "")
        self.assertEqual(entry["store"], "")
        self.assertEqual(entry["version"], "")
        self.assertIsNone(entry["sha256"])

    def test_gaps_listed_for_undocumented_row(self):
        entry = self.entries["pnlphjjfielecalmmjjdhjjninkbjdod"]
        self.assertEqual(set(entry["gaps"]), set(bl.ENRICHABLE_FIELDS))
        self.assertFalse(entry["documented"])

    def test_curated_row_has_no_gaps(self):
        entry = self.entries["cigkgjjhaklfppedcelcdnffcnfhmcen"]
        self.assertEqual(entry["gaps"], [])
        self.assertTrue(entry["documented"])
        self.assertEqual(entry["reason"], "Policy Violation")

    def test_source_preserved_verbatim(self):
        entry = self.entries["pnlphjjfielecalmmjjdhjjninkbjdod"]
        self.assertEqual(entry["source"], '"chrome-mal-ids" Dataset')
        self.assertFalse(entry["source_is_url"])

    def test_stats_report_coverage(self):
        stats = bl.blocklist_stats(self.entries)
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["documented"], 1)
        self.assertEqual(stats["incomplete"], 1)
        self.assertEqual(stats["missing_by_field"]["reason"], 1)


# ── Write-back ────────────────────────────────────────────────────────────────
class TestWriteBack(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="c1_bl_write_")
        self.path = write_sheet(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _rows(self):
        with open(self.path, encoding="cp1252", newline="") as handle:
            return list(csv.DictReader(handle))

    def test_fills_only_missing_columns(self):
        changed = bl.update_entry(self.path, "pnlphjjfielecalmmjjdhjjninkbjdod", {
            "extension_name": "FastSave", "reason": "Spyware",
            "version": "3.8.8", "store": "Chrome", "date": "8/29/2026",
            "sha256": "abc123",
        }, confidence="Medium", method="unit test")
        self.assertEqual(set(changed),
                         {"extension_name", "reason", "version", "store", "date", "sha256"})
        row = [r for r in self._rows()
               if r["Extension ID"] == "pnlphjjfielecalmmjjdhjjninkbjdod"][0]
        self.assertEqual(row["Extention Name"], "FastSave")
        self.assertEqual(row["Reason"], "Spyware")
        self.assertEqual(row["SHA256 Hash"], "abc123")

    def test_never_overwrites_curated_evidence(self):
        changed = bl.update_entry(self.path, "cigkgjjhaklfppedcelcdnffcnfhmcen", {
            "reason": "Malware", "extension_name": "Something Else",
        })
        self.assertEqual(changed, [])
        row = [r for r in self._rows()
               if r["Extension ID"] == "cigkgjjhaklfppedcelcdnffcnfhmcen"][0]
        self.assertEqual(row["Reason"], "Policy Violation")
        self.assertEqual(row["Extention Name"], "Whatsapp Bulk Messenger")

    def test_overwrite_flag_replaces_curated_evidence(self):
        changed = bl.update_entry(self.path, "cigkgjjhaklfppedcelcdnffcnfhmcen",
                                  {"reason": "Malware"}, overwrite=True)
        self.assertEqual(changed, ["reason"])

    def test_other_rows_and_header_untouched(self):
        before = self._rows()
        bl.update_entry(self.path, "pnlphjjfielecalmmjjdhjjninkbjdod", {"reason": "Adware"})
        after = self._rows()
        self.assertEqual(len(before), len(after))
        self.assertEqual(list(before[0].keys()), list(after[0].keys()))
        self.assertEqual(before[0], after[0])          # curated row byte-identical

    def test_unknown_id_is_a_no_op(self):
        self.assertEqual(bl.update_entry(self.path, "z" * 32, {"reason": "Adware"}), [])

    def test_audit_log_records_old_and_new(self):
        bl.update_entry(self.path, "pnlphjjfielecalmmjjdhjjninkbjdod",
                        {"reason": "Adware"}, confidence="High", method="unit test")
        log = os.path.join(self.dir, "blocklist_enrichment_log.csv")
        self.assertTrue(os.path.exists(log))
        with open(log, encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[-1]["field"], "reason")
        self.assertEqual(rows[-1]["old_value"], "Not yet confirmed")
        self.assertEqual(rows[-1]["new_value"], "Adware")
        self.assertEqual(rows[-1]["confidence"], "High")


# ── Name resolution and sheet-safe text ───────────────────────────────────────
class TestNameResolution(unittest.TestCase):
    def test_plain_manifest_name(self):
        name, prov = enrich.resolve_extension_name({"name": "  FastSave  "})
        self.assertEqual(name, "FastSave")
        self.assertEqual(prov, "manifest")

    def test_i18n_placeholder_resolved_from_locales(self):
        directory = tempfile.mkdtemp(prefix="c1_locale_")
        try:
            locale_dir = os.path.join(directory, "_locales", "en")
            os.makedirs(locale_dir)
            with open(os.path.join(locale_dir, "messages.json"), "w", encoding="utf-8") as handle:
                json.dump({"appName": {"message": "FastSave"}}, handle)
            name, prov = enrich.resolve_extension_name(
                {"name": "__MSG_appName__", "default_locale": "en"}, ext_path=directory)
            self.assertEqual(name, "FastSave")
            self.assertEqual(prov, "manifest_i18n")
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_falls_back_to_webstore_slug(self):
        name, prov = enrich.resolve_extension_name(
            {"name": "__MSG_appName__"},
            webstore_url="https://chromewebstore.google.com/detail/fast-save/"
                         "pnlphjjfielecalmmjjdhjjninkbjdod")
        self.assertEqual(name, "Fast Save")
        self.assertEqual(prov, "webstore_slug")

    def test_no_name_available(self):
        self.assertEqual(enrich.resolve_extension_name({}), ("", ""))

    def test_sheet_safe_strips_unrepresentable_characters(self):
        cleaned = enrich.sheet_safe("Ad–Blocker \U0001F600 Pro")
        cleaned.encode("cp1252")          # must not raise
        self.assertIn("Ad-Blocker", cleaned)

    def test_store_detection(self):
        self.assertEqual(enrich.store_from_url(
            "https://chromewebstore.google.com/detail/x/abc"), "Chrome")
        self.assertEqual(enrich.store_from_url(
            "https://microsoftedge.microsoft.com/addons/detail/abc"), "Edge")


# ── Reason derivation ─────────────────────────────────────────────────────────
def derive(**overrides):
    args = dict(
        manifest={}, features={}, source_code="", flags=[],
        ml_prob=0.0, anomaly_score=0.0, static_score=0.0,
        dynamic_score=0.0, sandbox_ran=False,
    )
    args.update(overrides)
    return enrich.derive_reason(**args)


class TestReasonDerivation(unittest.TestCase):
    def test_cookie_exfiltration_names_the_spyware_family(self):
        verdict = derive(flags=["COOKIE_EXFILTRATION_RISK"], sandbox_ran=True,
                         features={"has_cookies": 1, "has_all_urls": 1})
        self.assertEqual(verdict.reason, enrich.CATEGORY_EXFIL)
        self.assertTrue(verdict.rationale)

    def test_search_provider_override_is_search_hijacking(self):
        verdict = derive(manifest={"chrome_settings_overrides":
                                   {"search_provider": {"name": "x"}}})
        self.assertEqual(verdict.reason, enrich.CATEGORY_SEARCH_HIJACK)

    def test_native_messaging_is_bundling(self):
        verdict = derive(features={"has_nativeMessaging": 1, "has_downloads": 1},
                         source_code="chrome.downloads.download('setup.exe')")
        self.assertEqual(verdict.reason, enrich.CATEGORY_BUNDLING)

    def test_wallet_strings_plus_network_is_crypto_theft(self):
        verdict = derive(
            source_code="const mnemonic = seedPhrase; metamask; privateKey; fetch(url)",
            features={"xhr_fetch_count": 3})
        self.assertEqual(verdict.reason, enrich.CATEGORY_CRYPTO)

    def test_high_ml_probability_names_malware(self):
        verdict = derive(ml_prob=0.95, features={"has_storage": 1})
        self.assertEqual(verdict.reason, enrich.CATEGORY_MALWARE)

    def test_single_ad_string_does_not_earn_adware(self):
        # One "doubleclick" reference is not evidence of an ad-injection campaign.
        verdict = derive(source_code="https://doubleclick.net/pixel",
                         features={"has_content_scripts": 1, "has_all_urls": 1})
        self.assertNotEqual(verdict.reason, enrich.CATEGORY_ADWARE)

    def test_many_ad_networks_earns_adware(self):
        verdict = derive(
            source_code="doubleclick popunder adserver taboola outbrain aff_id",
            features={"has_content_scripts": 1, "has_all_urls": 1})
        self.assertEqual(verdict.reason, enrich.CATEGORY_ADWARE)

    def test_broad_permissions_alone_fall_back_to_policy_violation(self):
        verdict = derive(features={"has_all_urls": 1, "has_webRequest": 1,
                                   "has_tabs": 1, "total_permission_count": 9})
        self.assertEqual(verdict.reason, enrich.CATEGORY_POLICY)

    def test_no_evidence_falls_back_without_naming_a_threat(self):
        verdict = derive()
        self.assertEqual(verdict.reason, enrich.CATEGORY_SUSPICIOUS)
        self.assertEqual(verdict.confidence, "Low")

    def test_delisted_extension_gets_removal_reason_unknown(self):
        verdict = derive(code_available=False)
        self.assertEqual(verdict.reason, enrich.CATEGORY_REMOVED)

    def test_ml_probability_ignored_when_code_unavailable(self):
        # 11 of the 33 features are code counts; with no JS they are all zero,
        # so the probability must not be allowed to name a threat class.
        verdict = derive(ml_prob=0.99, code_available=False)
        self.assertNotEqual(verdict.reason, enrich.CATEGORY_MALWARE)
        self.assertIn("archived manifest", verdict.method)

    def test_every_derived_reason_uses_the_sheets_vocabulary(self):
        allowed = {
            enrich.CATEGORY_MALWARE, enrich.CATEGORY_SPYWARE, enrich.CATEGORY_EXFIL,
            enrich.CATEGORY_ADWARE, enrich.CATEGORY_SEARCH_HIJACK,
            enrich.CATEGORY_BUNDLING, enrich.CATEGORY_CRYPTO, enrich.CATEGORY_POLICY,
            enrich.CATEGORY_SUSPICIOUS, enrich.CATEGORY_REMOVED,
        }
        cases = [
            dict(flags=["COOKIE_EXFILTRATION_RISK"]),
            dict(ml_prob=0.95),
            dict(features={"has_nativeMessaging": 1}),
            dict(manifest={"chrome_url_overrides": {"newtab": "n.html"}}),
            dict(),
        ]
        for case in cases:
            self.assertIn(derive(**case).reason, allowed)

    def test_confidence_scales_with_evidence(self):
        weak = derive()
        strong = derive(flags=["COOKIE_EXFILTRATION_RISK", "KEYBOARD_MONITORING",
                               "DATA_POST_TO_EXTERNAL"],
                        features={"has_cookies": 1, "has_all_urls": 1,
                                  "cookie_in_code": 5, "has_history": 1},
                        sandbox_ran=True)
        self.assertEqual(weak.confidence, "Low")
        self.assertEqual(strong.confidence, "High")


# ── Analyzer contract ─────────────────────────────────────────────────────────
class TestAnalyzerBlocklistContract(unittest.TestCase):
    """The blocklist verdict itself must not change: MALICIOUS at 100."""

    @classmethod
    def setUpClass(cls):
        from core.c1 import analyzer
        cls.analyzer = analyzer
        analyzer._load_resources()
        if not analyzer._BLOCKLIST:
            raise unittest.SkipTest("finalized blocklist sheet not present")

    def _run(self, ext_id, manifest=None, code=""):
        return asyncio.run(self.analyzer.analyze_extension(
            json.dumps(manifest or {"name": "x", "version": "1.0"}), code, ext_id))

    def test_documented_row_takes_the_instant_path(self):
        documented = next((eid for eid, e in self.analyzer._BLOCKLIST.items()
                           if e and not bl.entry_gaps(e)), None)
        if not documented:
            self.skipTest("no fully documented row in the sheet")
        result = self._run(documented)
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["score"], 1.0)
        self.assertEqual(result["score_source"], "blocklist")
        self.assertIn("HASH_MATCH", result["flags"])
        self.assertTrue(result["static"]["blocklist_details"]["documented"])
        # Instant path: the models were never consulted.
        self.assertNotIn("measured_static_score", result["static"])

    def test_gapped_row_runs_the_models_and_keeps_the_verdict(self):
        gapped = next((eid for eid, e in self.analyzer._BLOCKLIST.items()
                       if e and bl.entry_gaps(e)), None)
        if not gapped:
            self.skipTest("every row is already documented")
        # persist=False equivalent: analysis on a manifest we made up should not
        # be written to the sheet, so the enrichment is disabled here and the
        # write-back path is covered by TestWriteBack instead.
        result = asyncio.run(self.analyzer.analyze_extension(
            json.dumps({"name": "x", "version": "1.0"}), "", gapped,
            enrich_blocklist=False))
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["score"], 1.0)
        self.assertEqual(result["score_source"], "blocklist")

    def test_unknown_id_is_not_a_blocklist_hit(self):
        result = self._run("a" * 32)
        self.assertNotEqual(result.get("score_source"), "blocklist")
        self.assertFalse(result["static"]["hash_match"])

    def test_probe_reports_gaps_without_analysis(self):
        gapped = next((eid for eid, e in self.analyzer._BLOCKLIST.items()
                       if e and bl.entry_gaps(e)), None)
        if not gapped:
            self.skipTest("every row is already documented")
        probe = self.analyzer.blocklist_probe(gapped)
        self.assertTrue(probe["match"])
        self.assertTrue(probe["needs_evidence"])
        self.assertTrue(probe["gaps"])


if __name__ == "__main__":
    print("\n=== C1 Blocklist Evidence Tests ===\n")
    unittest.main(verbosity=2)
