"""
C2 Alert Store Unit Tests — persistence of the individual alert log
Run from project root:  python test/C2/test_c2_alert_store.py
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c2.alert_store import C2AlertStore


def _alert(url="https://victim.example/login", verdict="PHISHING", score=91.5, ts=None):
    """One alert shaped the way core/main.py::analyze() stores them."""
    return {
        "url": url,
        "verdict": verdict,
        "risk_score": score,
        "timestamp": ts or datetime.now().isoformat(),
        "verified": False,
        "layers": [
            {"id": "L1", "name": "BitB Detection", "score": 1.0, "detail": "ML:1.00",
             "heuristic": 1.0,
             "evidence": {"features": {"n_iframes": 1, "max_zindex": 9999},
                          "flags": ["fixed-pos iframe"], "ml_prob": 0.9998}},
            {"id": "L4", "name": "Form Destination", "score": 0.85, "detail": "form->x",
             "evidence": {"off_domain_hosts": ["attacker-collector.xyz"],
                          "has_password_field": True}},
        ],
        "fusion": {"method": "weighted_sum", "pre_floor_risk": 33.9,
                   "floor_applied": "phishing", "final_risk": 60},
    }


class _StoreCase(unittest.TestCase):
    """Each test gets its own DB file — the real store lives at
    ~/.websentinel/c2_alerts.db and tests must never touch it."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="c2store_")
        self.store = C2AlertStore(os.path.join(self.dir, "c2_alerts.db"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class TestRoundTrip(_StoreCase):

    def test_add_returns_an_id(self):
        row = self.store.add_alert(_alert())
        self.assertIsInstance(row["id"], int)
        self.assertEqual(self.store.count(), 1)

    def test_get_alert_returns_the_full_record(self):
        stored = self.store.add_alert(_alert())
        got = self.store.get_alert(stored["id"])
        self.assertEqual(got["url"], "https://victim.example/login")
        self.assertEqual(got["verdict"], "PHISHING")
        self.assertAlmostEqual(got["risk_score"], 91.5)

    def test_layer_evidence_survives_the_json_column(self):
        # This is the whole point of the store: the per-layer measurements have
        # to come back out intact, not just the score.
        stored = self.store.add_alert(_alert())
        got = self.store.get_alert(stored["id"])
        l1 = next(l for l in got["layers"] if l["id"] == "L1")
        self.assertEqual(l1["evidence"]["features"]["max_zindex"], 9999)
        self.assertIn("fixed-pos iframe", l1["evidence"]["flags"])
        l4 = next(l for l in got["layers"] if l["id"] == "L4")
        self.assertIn("attacker-collector.xyz", l4["evidence"]["off_domain_hosts"])

    def test_fusion_breakdown_survives(self):
        stored = self.store.add_alert(_alert())
        got = self.store.get_alert(stored["id"])
        self.assertEqual(got["fusion"]["method"], "weighted_sum")
        self.assertEqual(got["fusion"]["floor_applied"], "phishing")
        self.assertAlmostEqual(got["fusion"]["pre_floor_risk"], 33.9)

    def test_get_alert_returns_none_for_unknown_id(self):
        self.assertIsNone(self.store.get_alert(999999))

    def test_verified_flag_round_trips_as_bool(self):
        a = _alert(verdict="VERIFIED", score=0.0)
        a["verified"] = True
        got = self.store.get_alert(self.store.add_alert(a)["id"])
        self.assertIs(got["verified"], True)


class TestListing(_StoreCase):

    def test_most_recent_first(self):
        for i in range(5):
            self.store.add_alert(_alert(url=f"https://e{i}.test/"))
        rows = self.store.list_alerts(10)
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]["url"], "https://e4.test/")

    def test_limit_is_respected(self):
        for i in range(8):
            self.store.add_alert(_alert(url=f"https://e{i}.test/"))
        self.assertEqual(len(self.store.list_alerts(3)), 3)

    def test_verdict_filter(self):
        self.store.add_alert(_alert(verdict="PHISHING"))
        self.store.add_alert(_alert(verdict="SAFE"))
        self.store.add_alert(_alert(verdict="SAFE"))
        self.assertEqual(len(self.store.list_alerts(50, verdict="SAFE")), 2)
        self.assertEqual(len(self.store.list_alerts(50, verdict="PHISHING")), 1)

    def test_verdict_filter_is_case_insensitive(self):
        self.store.add_alert(_alert(verdict="PHISHING"))
        self.assertEqual(len(self.store.list_alerts(50, verdict="phishing")), 1)

    def test_since_filter(self):
        old = (datetime.now() - timedelta(days=3)).isoformat()
        self.store.add_alert(_alert(ts=old))
        self.store.add_alert(_alert())
        cutoff = (datetime.now() - timedelta(days=1)).isoformat()
        self.assertEqual(len(self.store.list_alerts(50, since=cutoff)), 1)

    def test_a_filtered_query_sees_past_the_cache(self):
        # The cache only holds the newest 100 rows. A filtered listing must query
        # the table, or a match older than that window would be invisible.
        self.store.add_alert(_alert(verdict="SAFE", url="https://needle.test/"))
        for i in range(120):
            self.store.add_alert(_alert(verdict="PHISHING", url=f"https://n{i}.test/"))
        hits = self.store.list_alerts(500, verdict="SAFE")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["url"], "https://needle.test/")


class TestPersistenceAndMaintenance(_StoreCase):

    def test_alerts_survive_a_restart(self):
        # The behaviour C2 did not have: the in-memory list was lost on restart.
        stored = self.store.add_alert(_alert())
        reopened = C2AlertStore(self.store.path)
        self.assertEqual(reopened.count(), 1)
        self.assertEqual(reopened.get_alert(stored["id"])["url"],
                         "https://victim.example/login")

    def test_cache_and_db_agree(self):
        for i in range(4):
            self.store.add_alert(_alert(url=f"https://e{i}.test/"))
        from_cache = self.store.list_alerts(4)
        from_db = C2AlertStore(self.store.path).list_alerts(4)
        self.assertEqual([r["url"] for r in from_cache], [r["url"] for r in from_db])

    def test_purge_removes_only_old_rows(self):
        self.store.add_alert(_alert(ts=(datetime.now() - timedelta(days=40)).isoformat()))
        self.store.add_alert(_alert())
        self.assertEqual(self.store.purge_older_than(30), 1)
        self.assertEqual(self.store.count(), 1)

    def test_purge_refreshes_the_cache(self):
        self.store.add_alert(_alert(ts=(datetime.now() - timedelta(days=40)).isoformat()))
        self.store.purge_older_than(30)
        self.assertEqual(len(self.store.list_alerts(50)), 0)

    def test_db_path_isolation(self):
        self.assertTrue(self.store.path.startswith(self.dir))
        self.assertNotIn(".websentinel", self.store.path)


class TestRobustness(_StoreCase):

    def test_missing_fields_get_defaults(self):
        row = self.store.add_alert({"url": "https://bare.test/"})
        got = self.store.get_alert(row["id"])
        self.assertEqual(got["verdict"], "SAFE")
        self.assertEqual(got["layers"], [])
        self.assertEqual(got["fusion"], {})

    def test_timestamp_is_generated_when_absent(self):
        row = self.store.add_alert({"url": "https://bare.test/"})
        self.assertTrue(self.store.get_alert(row["id"])["timestamp"])

    def test_non_serialisable_evidence_does_not_raise(self):
        # add_alert dumps with default=str, so an odd value degrades to a string
        # rather than taking the analysis down with it.
        a = _alert()
        a["layers"][0]["evidence"]["when"] = datetime.now()
        row = self.store.add_alert(a)
        self.assertIsInstance(self.store.get_alert(row["id"])["layers"], list)

    def test_stored_json_is_valid(self):
        self.store.add_alert(_alert())
        import sqlite3
        with sqlite3.connect(self.store.path) as conn:
            raw = conn.execute("SELECT layers_json, fusion_json FROM c2_alerts").fetchone()
        json.loads(raw[0])
        json.loads(raw[1])


if __name__ == "__main__":
    print("\n=== C2 Alert Store Unit Tests ===\n")
    unittest.main(verbosity=2)
