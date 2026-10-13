"""
C1 Unit Tests - verdict rule and what history gives back
Run from project root:  python test/C1/test_c1_verdict.py

Two defects this guards against:

1. A score shown as 70 labelled SUSPICIOUS. The dashboard rounds 69.84 to 70, the
   malicious threshold, but the verdict was decided on 69.84. The verdict is now
   decided on the whole number the reader sees.
2. The anomaly score reading 0 for every analysis reopened from history. It was
   saved inside the report, never read back.
"""
import os
import sys
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c1.report import build_report, restate_verdict, verdict_for


class TestVerdictRule(unittest.TestCase):

    def test_a_score_shown_as_70_is_malicious(self):
        for score in (69.5, 69.84, 69.99, 70.0, 70.4, 100):
            self.assertEqual(verdict_for(score), "MALICIOUS", score)

    def test_just_under_stays_suspicious(self):
        for score in (40, 55.5, 69.0, 69.49):
            self.assertEqual(verdict_for(score), "SUSPICIOUS", score)

    def test_the_lower_threshold_follows_the_same_rule(self):
        self.assertEqual(verdict_for(39.49), "SAFE")
        self.assertEqual(verdict_for(39.5), "SUSPICIOUS")
        self.assertEqual(verdict_for(0), "SAFE")

    def test_it_matches_what_the_dashboard_displays(self):
        # the dashboard shows Math.round(score); the verdict must agree with that number
        for tenth in range(0, 1001):
            score = tenth / 10
            shown = int(score + 0.5)
            expected = "MALICIOUS" if shown >= 70 else "SUSPICIOUS" if shown >= 40 else "SAFE"
            self.assertEqual(verdict_for(score), expected, score)

    def test_the_analyzer_uses_the_same_function(self):
        with open(os.path.join(_ROOT, "core", "c1", "analyzer.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertIn("verdict = verdict_for(final_score)", src)
        self.assertNotIn("final_score >= 70", src)


class TestStoredReportRestatement(unittest.TestCase):

    def _report(self, verdict, score):
        result = {"score": score, "verdict": verdict, "flags": [], "extension_id": "abc",
                  "static": {"score": score, "ml_score": score, "hash_match": False, "anomaly_score": 0.4},
                  "dynamic": {"score": 0.0, "executed": False}}
        rep = build_report(result)
        rep["plain_summary"] = {"SUSPICIOUS": "This extension behaves in ways worth checking before you install it.",
                                "MALICIOUS": "This extension is dangerous and should not be installed."}[verdict] + " It can read your data."
        return rep

    def test_the_text_that_states_the_verdict_is_rewritten(self):
        out = restate_verdict(self._report("SUSPICIOUS", 0.6984), "SUSPICIOUS", "MALICIOUS")
        self.assertEqual(out["risk_level"], "CRITICAL")
        self.assertTrue(out["recommendation"].startswith("Block installation"))
        self.assertTrue(out["summary"].startswith("MALICIOUS extension detected"))
        self.assertTrue(out["plain_summary"].startswith("This extension is dangerous"))
        self.assertTrue(out["plain_summary"].endswith("It can read your data."))

    def test_everything_else_is_left_as_stored(self):
        rep = self._report("SUSPICIOUS", 0.6984)
        out = restate_verdict(rep, "SUSPICIOUS", "MALICIOUS")
        for key in ("score_breakdown", "flags", "identity", "permissions"):
            self.assertEqual(out.get(key), rep.get(key), key)

    def test_the_original_is_not_changed(self):
        rep = self._report("SUSPICIOUS", 0.6984)
        restate_verdict(rep, "SUSPICIOUS", "MALICIOUS")
        self.assertEqual(rep["risk_level"], "HIGH")

    def test_the_same_verdict_changes_nothing(self):
        rep = self._report("SUSPICIOUS", 0.55)
        self.assertEqual(restate_verdict(rep, "SUSPICIOUS", "SUSPICIOUS"), rep)


class TestHistoryReadBack(unittest.TestCase):

    def setUp(self):
        from core.c1 import db
        self.db = db
        self._orig = db._DB_PATH
        db._DB_PATH = os.path.join(tempfile.mkdtemp(prefix="c1_verdict_"), "t.db")

    def tearDown(self):
        self.db._DB_PATH = self._orig

    def _save(self, score, verdict, anomaly=0.486, ext="abc", **extra):
        result = {"score": score, "verdict": verdict, "detail": "d", "flags": [], "extension_id": ext,
                  "timestamp": "2026-10-12T10:00:00", "source": "upload",
                  "static": {"score": score, "ml_score": score, "hash_match": False, "anomaly_score": anomaly},
                  "dynamic": {"score": 0.0, "executed": False}}
        result.update(extra)
        result["report"] = build_report(result)
        self.db.save_result(result)
        return self.db.get_history(1)[0]

    # -- the anomaly score ---------------------------------------------------------------------
    def test_the_anomaly_score_comes_back(self):
        row = self._save(0.5, "SUSPICIOUS", anomaly=0.486)
        self.assertAlmostEqual(row["static"]["anomaly_score"], 0.486, places=3)

    def test_a_zero_anomaly_is_a_real_value(self):
        row = self._save(0.2, "SAFE", anomaly=0.0)
        self.assertEqual(row["static"]["anomaly_score"], 0.0)

    def test_a_row_with_none_recorded_leaves_it_unset(self):
        import json, sqlite3
        self._save(0.5, "SUSPICIOUS")
        con = sqlite3.connect(self.db._DB_PATH)
        rep = json.loads(con.execute("SELECT report FROM c1_analyses").fetchone()[0])
        rep["score_breakdown"].pop("anomaly_score")
        con.execute("UPDATE c1_analyses SET report=?", (json.dumps(rep),))
        con.commit(); con.close()
        self.assertNotIn("anomaly_score", self.db.get_history(1)[0]["static"])

    # -- the verdict ---------------------------------------------------------------------------
    def test_a_row_labelled_by_the_old_rule_is_corrected(self):
        row = self._save(0.6984, "SUSPICIOUS")           # saved as 69.84 and labelled SUSPICIOUS
        self.assertEqual(row["verdict"], "MALICIOUS")
        self.assertEqual(row["report"]["risk_level"], "CRITICAL")
        self.assertTrue(row["report"]["summary"].startswith("MALICIOUS extension detected"))

    def test_a_correct_row_is_untouched(self):
        for score, verdict in ((0.70, "MALICIOUS"), (0.6949, "SUSPICIOUS"), (0.2, "SAFE"), (0.55, "SUSPICIOUS")):
            self.assertEqual(self._save(score, verdict)["verdict"], verdict, score)

    def test_a_deliberate_override_is_not_second_guessed(self):
        # a verdict the old rule would not have produced (e.g. an authority decision) stays as stored
        row = self._save(0.55, "MALICIOUS", score_source="blocklist")
        self.assertEqual(row["verdict"], "MALICIOUS")
        row = self._save(0.55, "SAFE")
        self.assertEqual(row["verdict"], "SAFE")

    def test_the_stored_row_itself_is_not_rewritten(self):
        import sqlite3
        self._save(0.6984, "SUSPICIOUS")
        con = sqlite3.connect(self.db._DB_PATH)
        self.assertEqual(con.execute("SELECT verdict FROM c1_analyses").fetchone()[0], "SUSPICIOUS")
        con.close()


if __name__ == "__main__":
    unittest.main(verbosity=1)
