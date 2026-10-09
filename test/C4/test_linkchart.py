"""
C4 link chart tests -- graph builder + static SVG, run against the planted breach case.
Run from project root:  python test/C4/test_linkchart.py
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c4 import demo_case
from core.c4 import linkchart as lc
from core.c4.linkchart import build_link_chart, render_svg
from core.c4.reporter import generate_html_report

_STATE = {}


def setUpModule():
    root = tempfile.mkdtemp(prefix="c4_linkchart_")
    info = demo_case.build_case_profile(root)
    _STATE["root"], _STATE["info"] = root, info
    _STATE["result"] = demo_case.run_case_pipeline(info["root"])
    _STATE["graph"] = build_link_chart(_STATE["result"])


def tearDownModule():
    shutil.rmtree(_STATE.get("root", ""), ignore_errors=True)


def _by_id(g):
    return {n["id"]: n for n in g["nodes"]}


class TestPlantedBreach(unittest.TestCase):

    def setUp(self):
        self.g = _STATE["graph"]
        self.nodes = _by_id(self.g)
        self.p = _STATE["info"]["planted"]

    def test_has_domain_file_and_account_nodes(self):
        types = {n["type"] for n in self.g["nodes"]}
        self.assertEqual(types, {"domain", "file", "account"})

    def test_the_breach_domain_is_a_high_risk_node(self):
        n = self.nodes["d:" + self.p["breach_domain"]]
        self.assertGreaterEqual(n["risk"], 80)
        self.assertGreater(n["flagged_count"], 0)

    def test_download_links_the_source_domain_to_the_file(self):
        fid = next(i for i in self.nodes if i.startswith("f:payroll_update.exe"))
        e = [x for x in self.g["edges"] if x["kind"] == "download" and x["target"] == fid]
        self.assertEqual(e[0]["source"], "d:" + self.p["breach_domain"])

    def test_exfil_link_goes_from_the_file_to_the_follow_on_domain(self):
        ex = [e for e in self.g["edges"] if e["kind"] == "exfil"]
        self.assertEqual(len(ex), 1)
        self.assertTrue(ex[0]["source"].startswith("f:payroll_update.exe"))
        self.assertEqual(ex[0]["target"], "d:" + self.p["exfil_domain"])
        self.assertTrue(ex[0]["flagged"])
        self.assertIn("T1567", ex[0]["techniques"])

    def test_credential_reuse_links_the_account_to_every_domain(self):
        aid = "a:" + self.p["victim_user"]
        cred = [e for e in self.g["edges"] if e["kind"] == "credential" and e["source"] == aid]
        self.assertEqual(len(cred), 3)
        self.assertTrue(all(e["flagged"] for e in cred))
        self.assertTrue(all(e["label"] == "reused login" for e in cred))

    def test_attack_chain_steps_are_marked_and_connected(self):
        self.assertTrue(self.g["chains"])
        chain = self.g["chains"][0]
        self.assertGreaterEqual(len(chain["steps"]), 3)
        self.assertEqual(chain["steps"][0], "d:" + self.p["breach_domain"])
        for nid in chain["steps"]:
            self.assertIn(chain["id"], self.nodes[nid]["chains"])
        hot = {e["id"] for e in self.g["edges"] if e["chain"]}
        self.assertTrue(set(chain["edges"]) <= hot)

    def test_mitre_techniques_are_attached_to_the_breach_domain(self):
        self.assertIn("T1105", self.nodes["d:" + self.p["breach_domain"]]["techniques"])

    def test_navigation_flow_links_exist_between_domains(self):
        nav = [e for e in self.g["edges"] if e["kind"] == "navigation"]
        self.assertGreater(len(nav), 5)
        self.assertTrue(all(e["source"] != e["target"] for e in nav))

    def test_every_edge_endpoint_is_a_node(self):
        for e in self.g["edges"]:
            self.assertIn(e["source"], self.nodes)
            self.assertIn(e["target"], self.nodes)

    def test_node_events_are_capped_and_carry_no_secrets(self):
        for n in self.g["nodes"]:
            self.assertLessEqual(len(n["events"]), lc.MAX_NODE_EVENTS)
        blob = json.dumps(self.g).lower()
        self.assertNotIn("password", blob)
        self.assertNotIn("master key", blob)

    def test_output_is_deterministic(self):
        again = build_link_chart(_STATE["result"])
        self.assertEqual(json.dumps(again, sort_keys=True), json.dumps(self.g, sort_keys=True))

    def test_the_builder_does_not_mutate_the_result(self):
        before = json.dumps(_STATE["result"]["events"], default=str, sort_keys=True)
        build_link_chart(_STATE["result"])
        self.assertEqual(json.dumps(_STATE["result"]["events"], default=str, sort_keys=True), before)


class TestSizeControl(unittest.TestCase):

    def _result(self, n_domains):
        events = []
        for i in range(n_domains):
            events.append({"artifact_type": "history", "timestamp": f"2026-10-08T10:{i // 60:02d}:{i % 60:02d}",
                           "risk_flag": False, "anomaly_score": 0, "anomaly_reasons": [],
                           "detail": {"url": f"https://site{i}.example/", "title": "t"}})
        return {"events": events, "correlation": {}, "mitre_result": {"all_findings": []}}

    def test_a_long_tail_of_quiet_domains_is_folded_into_one_node(self):
        g = build_link_chart(self._result(400))
        doms = [n for n in g["nodes"] if n["type"] == "domain"]
        self.assertLessEqual(len(doms), lc.MAX_DOMAINS + 1)
        other = [n for n in doms if n.get("collapsed")]
        self.assertEqual(len(other), 1)
        self.assertEqual(g["stats"]["total_domains"], 400)
        self.assertEqual(g["stats"]["folded_domains"], 400 - lc.MAX_DOMAINS)
        self.assertTrue(g["stats"]["truncated"])
        self.assertLessEqual(len(g["edges"]), lc.MAX_EDGES)

    def test_flagged_domains_are_never_folded(self):
        r = self._result(300)
        r["events"][299]["risk_flag"] = True
        r["events"][299]["anomaly_score"] = 80
        g = build_link_chart(r)
        self.assertIn("d:site299.example", _by_id(g))

    def test_an_empty_result_gives_an_empty_chart(self):
        g = build_link_chart({})
        self.assertEqual(g["nodes"], [])
        self.assertEqual(render_svg(g), "")


class TestSvgAndReport(unittest.TestCase):

    def test_svg_is_self_contained_and_has_the_entities(self):
        svg = render_svg(_STATE["graph"])
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn("secure-payroll-login.top", svg)
        self.assertNotIn("<script", svg)
        self.assertNotIn("http://", svg.replace("http://www.w3.org", ""))

    def test_labels_are_html_escaped(self):
        g = {"nodes": [{"id": "d:x", "type": "domain", "label": "<img src=x onerror=alert(1)>", "risk": 90,
                        "event_count": 3, "flagged_count": 1, "artifact_types": [], "techniques": [],
                        "chains": [], "events": []}], "edges": [], "chains": [], "stats": {"nodes": 1}}
        svg = render_svg(g)
        self.assertNotIn("<img", svg)
        self.assertIn("&lt;img", svg)

    def test_the_html_report_gets_a_link_chart_section(self):
        html = generate_html_report(_STATE["result"])
        self.assertIn("Link Chart", html)
        self.assertIn('class="lc-svg"', html)
        self.assertIn("Attack chain / exfiltration link", html)

    def test_the_report_still_renders_without_events(self):
        html = generate_html_report({})
        self.assertNotIn('class="lc-svg"', html)
        self.assertIn("No findings", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
