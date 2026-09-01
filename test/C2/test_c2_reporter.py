"""
C2 Reporter Unit Tests — HTML report, CSV and SIEM export
Run from project root:  python test/C2/test_c2_reporter.py
"""
import csv
import io
import json
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c2.reporter import (generate_html_report, generate_csv,
                              generate_siem_export, report_filename)


def _alert(alert_id=7, verdict="PHISHING", score=60.0):
    return {
        "id": alert_id,
        "url": "https://victim.example/login",
        "verdict": verdict,
        "risk_score": score,
        "timestamp": "2026-08-30T19:25:30",
        "verified": False,
        "layers": [
            {"id": "L1", "name": "BitB Detection", "score": 1.0,
             "detail": "ML:1.00 | fixed-pos iframe",
             "evidence": {"features": {"n_iframes": 1, "max_zindex": 9999},
                          "flags": ["fixed-pos iframe", "high z-index"],
                          "ml_prob": 0.9998}},
            {"id": "L4", "name": "Form Destination", "score": 0.85,
             "detail": "form->attacker-collector.xyz",
             "evidence": {"off_domain_hosts": ["attacker-collector.xyz"],
                          "has_password_field": True, "flags": ["password field"]}},
            {"id": "L5", "name": "Reputation Check", "score": 0.0,
             "detail": "GSB key not configured",
             "evidence": {"gsb_queried": False, "phishtank_hit": False}},
        ],
        "fusion": {"method": "weighted_sum", "pre_floor_risk": 33.9,
                   "floor_applied": "phishing", "final_risk": 60},
    }


class TestHtmlReport(unittest.TestCase):

    def setUp(self):
        self.html = generate_html_report(_alert())

    def test_is_a_complete_document(self):
        self.assertTrue(self.html.startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", self.html)

    def test_shows_verdict_url_and_score(self):
        self.assertIn("PHISHING", self.html)
        self.assertIn("victim.example/login", self.html)
        self.assertIn("60", self.html)

    def test_lists_every_layer_that_ran(self):
        for lid in ("L1", "L4", "L5"):
            self.assertIn(f">{lid}<", self.html)
        self.assertIn("BitB Detection", self.html)

    def test_renders_the_layer_evidence(self):
        # A report that only restated the scores would say no more than the
        # alert card already does — the evidence is the reason to export it.
        self.assertIn("Feature vector", self.html)
        self.assertIn("max_zindex", self.html)
        self.assertIn("9999", self.html)
        self.assertIn("attacker-collector.xyz", self.html)

    def test_renders_the_signal_chips(self):
        self.assertIn("Signals tripped", self.html)
        self.assertIn("fixed-pos iframe", self.html)

    def test_renders_the_fusion_breakdown(self):
        self.assertIn("Score fusion", self.html)
        self.assertIn("weighted_sum", self.html)
        self.assertIn("pre_floor_risk", self.html)

    def test_is_self_contained(self):
        # No CDN, webfont or remote image — it has to render from a saved file.
        import re
        self.assertIsNone(re.search(r'(src|href)\s*=\s*["\']https?://', self.html))

    def test_has_a_print_stylesheet(self):
        self.assertIn("@media print", self.html)

    def test_escapes_html_in_the_url(self):
        evil = _alert()
        evil["url"] = 'https://x.test/<script>alert(1)</script>'
        out = generate_html_report(evil)
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_handles_an_alert_with_no_layers(self):
        bare = _alert()
        bare["layers"] = []
        bare["fusion"] = {}
        out = generate_html_report(bare)
        self.assertIn("No layers ran", out)
        self.assertIn("No fusion breakdown", out)

    def test_verdict_colour_tracks_the_verdict(self):
        self.assertIn("#dc2626", generate_html_report(_alert(verdict="PHISHING")))
        self.assertIn("#059669", generate_html_report(_alert(verdict="SAFE")))


class TestCsvExport(unittest.TestCase):

    def setUp(self):
        self.rows = list(csv.reader(io.StringIO(generate_csv([_alert(1), _alert(2)]))))

    def test_header_then_one_row_per_alert(self):
        self.assertEqual(len(self.rows), 3)

    def test_header_has_a_column_per_layer(self):
        header = self.rows[0]
        for lid in ("L1", "L2", "L3", "L4", "L5", "L6"):
            self.assertIn(f"{lid}_score", header)

    def test_core_columns_present(self):
        for col in ("id", "timestamp", "url", "verdict", "risk_score",
                    "fusion_method", "floor_applied", "flags"):
            self.assertIn(col, self.rows[0])

    def test_layer_scores_land_in_their_column(self):
        header, row = self.rows[0], self.rows[1]
        self.assertEqual(row[header.index("L1_score")], "1.0")
        self.assertEqual(row[header.index("L4_score")], "0.85")

    def test_missing_layer_leaves_an_empty_cell(self):
        header, row = self.rows[0], self.rows[1]
        self.assertEqual(row[header.index("L2_score")], "")

    def test_flags_are_prefixed_by_layer(self):
        header, row = self.rows[0], self.rows[1]
        self.assertIn("L1:fixed-pos iframe", row[header.index("flags")])

    def test_empty_input_still_writes_a_header(self):
        rows = list(csv.reader(io.StringIO(generate_csv([]))))
        self.assertEqual(len(rows), 1)


class TestSiemExport(unittest.TestCase):

    def setUp(self):
        self.doc = generate_siem_export([_alert(1), _alert(2, verdict="SUSPICIOUS")])

    def test_envelope_matches_the_c4_shape(self):
        # C4 emits the same keys, so one ingest pipeline handles both components.
        for key in ("export_type", "export_version", "generated_at",
                    "total_events", "events"):
            self.assertIn(key, self.doc)
        self.assertEqual(self.doc["export_type"], "C2_SIEM_Export")

    def test_total_matches_event_count(self):
        self.assertEqual(self.doc["total_events"], len(self.doc["events"]))
        self.assertEqual(self.doc["total_events"], 2)

    def test_event_carries_the_standard_fields(self):
        e = self.doc["events"][0]
        for key in ("timestamp", "source", "event_type", "severity", "score", "url"):
            self.assertIn(key, e)
        self.assertEqual(e["source"], "C2-PhishingDetector")

    def test_severity_maps_from_verdict(self):
        self.assertEqual(self.doc["events"][0]["severity"], "High")
        self.assertEqual(self.doc["events"][1]["severity"], "Medium")

    def test_triggered_signals_are_layer_prefixed(self):
        self.assertIn("L1:fixed-pos iframe", self.doc["events"][0]["triggered_signals"])

    def test_evidence_and_fusion_are_carried(self):
        e = self.doc["events"][0]
        self.assertIn("L1", e["evidence"])
        self.assertEqual(e["fusion"]["method"], "weighted_sum")

    def test_is_json_serialisable(self):
        json.dumps(self.doc, default=str)

    def test_empty_input_yields_an_empty_export(self):
        doc = generate_siem_export([])
        self.assertEqual(doc["total_events"], 0)
        self.assertEqual(doc["events"], [])


class TestReportFilename(unittest.TestCase):

    def test_is_prefixed_and_timestamped(self):
        name = report_filename("report")
        self.assertTrue(name.startswith("c2_report_"))
        self.assertRegex(name, r"^c2_report_\d{8}_\d{6}$")


if __name__ == "__main__":
    print("\n=== C2 Reporter Unit Tests ===\n")
    unittest.main(verbosity=2)
