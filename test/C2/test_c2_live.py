"""
C2 Live Analysis tests -- reasons, per-layer progress events, whitelist action.
Run from project root:  python test/C2/test_c2_live.py
"""
import asyncio
import os
import sys
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core import main as m


def _layer(lid, score, detail="", name=None):
    return {"id": lid, "name": name or lid, "score": score, "detail": detail}


class TestReasons(unittest.TestCase):

    def test_top_three_layers_above_the_warning_line_in_score_order(self):
        layers = [_layer("L1", .95, "fixed-pos iframe", "BitB Detection"),
                  _layer("L2", .30, "free host", "URL Analysis"),
                  _layer("L3", .10, "", "Visual Similarity"),
                  _layer("L4", .70, "form->evil", "Form Destination"),
                  _layer("L6", .50, "keylogger", "Runtime Behavior")]
        out = m._c2_build_reasons(layers, "PHISHING")
        self.assertEqual(len(out), 3)
        self.assertTrue(out[0].startswith("BitB Detection (95%)"))
        self.assertTrue(out[1].startswith("Form Destination (70%)"))
        self.assertTrue(out[2].startswith("Runtime Behavior (50%)"))
        self.assertFalse(any("Visual Similarity" in r for r in out))

    def test_a_clean_page_says_nothing_exceeded_the_line(self):
        out = m._c2_build_reasons([_layer("L1", .02), _layer("L2", .1)], "SAFE")
        self.assertEqual(out, ["No detection layer exceeded the warning line"])

    def test_fusion_floor_is_explained(self):
        out = m._c2_build_reasons([_layer("L1", 1.0, "x", "BitB")], "PHISHING",
            {"floor_applied": "phishing", "pre_floor_risk": 33.9, "final_risk": 60})
        self.assertTrue(any("hard rule" in r and "34" in r and "60" in r for r in out))

    def test_safe_verdict_with_a_fired_signal_explains_why_it_is_still_safe(self):
        out = m._c2_build_reasons([_layer("L2", .99, "ML model score", "URL Analysis")], "SAFE")
        self.assertIn("below the suspicious threshold", out[0])
        self.assertTrue(out[1].startswith("URL Analysis (99%)"))

    def test_verified_domain_without_layers(self):
        out = m._c2_build_reasons([], "VERIFIED", None, verified=True)
        self.assertIn("Verified domain", out[0])

    def test_long_detail_is_trimmed(self):
        out = m._c2_build_reasons([_layer("L1", .9, "x" * 500, "BitB")], "PHISHING")
        self.assertLess(len(out[0]), 200)


class TestProgressEvents(unittest.TestCase):

    def _run(self, coro):
        return asyncio.run(coro)

    def test_no_events_without_a_live_context(self):
        sent = []
        async def fake_broadcast(d): sent.append(d)
        with mock.patch.object(m, "_broadcast", fake_broadcast):
            self._run(m._c2_emit_layer("L1", "BitB", {"score": .5, "detail": "d"}))
        self.assertEqual(sent, [])

    def test_a_layer_event_carries_tab_url_and_row(self):
        sent = []
        async def fake_broadcast(d): sent.append(d)
        async def go():
            m._c2_live_ctx.set({"tab_id": 3, "url": "https://x.test/"})
            await m._c2_emit_layer("L2", "URL Analysis", {"score": .42345678, "detail": "d"})
        with mock.patch.object(m, "_broadcast", fake_broadcast):
            self._run(go())
        self.assertEqual(sent[0]["type"], "c2_layer")
        self.assertEqual(sent[0]["tab_id"], 3)
        self.assertEqual(sent[0]["layer"]["id"], "L2")
        self.assertEqual(sent[0]["layer"]["score"], 0.4235)

    def test_an_exception_is_reported_as_a_zero_score_error_row(self):
        sent = []
        async def fake_broadcast(d): sent.append(d)
        async def go():
            m._c2_live_ctx.set({"tab_id": 1, "url": "u"})
            await m._c2_emit_layer("L5", "Reputation", RuntimeError("boom"))
        with mock.patch.object(m, "_broadcast", fake_broadcast):
            self._run(go())
        self.assertEqual(sent[0]["layer"]["score"], 0.0)
        self.assertIn("boom", sent[0]["layer"]["detail"])

    def test_analyze_streams_every_layer_and_keeps_the_same_result(self):
        sent = []
        async def fake_broadcast(d): sent.append(d)
        async def go():
            m._c2_live_ctx.set({"tab_id": 9, "url": "https://victim.example/login"})
            return await m.analyze(m.AnalyzeReq(url="https://victim.example/login",
                                                dom="<html><body>hi</body></html>"))
        with mock.patch.object(m, "_broadcast", fake_broadcast), \
             mock.patch.object(m, "_store_c2_alert", lambda a: {}), \
             mock.patch.object(m, "is_verified", lambda u: False):
            result = self._run(go())
        streamed = {e["layer"]["id"] for e in sent if e["type"] == "c2_layer"}
        self.assertEqual(streamed, {l["id"] for l in result["layers"]})
        self.assertIn("reasons", result)

    def test_analyze_is_silent_for_direct_calls(self):
        sent = []
        async def fake_broadcast(d): sent.append(d)
        async def go():
            m._c2_live_ctx.set(None)
            return await m.analyze(m.AnalyzeReq(url="https://victim.example/login", dom="<html></html>"))
        with mock.patch.object(m, "_broadcast", fake_broadcast), \
             mock.patch.object(m, "_store_c2_alert", lambda a: {}), \
             mock.patch.object(m, "is_verified", lambda u: False):
            self._run(go())
        self.assertEqual([e for e in sent if e["type"] == "c2_layer"], [])


class TestStartAndLayers(unittest.TestCase):

    def test_skip_prefixes_and_whitelist_do_not_start(self):
        with mock.patch.dict(m.settings, {"whitelist": ["trusted.example"]}):
            self.assertFalse(m._c2_will_analyze("about:blank"))
            self.assertFalse(m._c2_will_analyze("https://trusted.example/x"))
            self.assertTrue(m._c2_will_analyze("https://other.example/x"))

    def test_enabled_layers_and_verified_gate(self):
        layers = {"l1": True, "l2": False, "l3": True, "l4": True, "l5": True, "l6": False}
        with mock.patch.dict(m.settings, {"layers": layers}), mock.patch.object(m, "is_verified", lambda u: False):
            self.assertEqual(m._c2_layers_for("https://a.test"), ["L1", "L3", "L4", "L5"])
        with mock.patch.dict(m.settings, {"layers": layers}), mock.patch.object(m, "is_verified", lambda u: True):
            self.assertEqual(m._c2_layers_for("https://google.com"), ["L5"])


class TestThumbnail(unittest.TestCase):

    def test_screenshot_is_downscaled_to_a_small_jpeg(self):
        import base64, io
        from PIL import Image
        buf = io.BytesIO()
        Image.new("RGB", (1280, 800), (30, 60, 200)).save(buf, format="JPEG", quality=75)
        out = m._c2_make_thumbnail(base64.b64encode(buf.getvalue()).decode())
        self.assertTrue(out.startswith("data:image/jpeg;base64,"))
        img = Image.open(io.BytesIO(base64.b64decode(out.split(",", 1)[1])))
        self.assertLessEqual(img.width, 320)
        self.assertLess(len(out), 20000)

    def test_garbage_input_gives_an_empty_string(self):
        self.assertEqual(m._c2_make_thumbnail("not-an-image"), "")


class TestWhitelistEndpoint(unittest.TestCase):

    def setUp(self):
        from fastapi.testclient import TestClient
        self.client = TestClient(m.app)
        self._saved = list(m.settings.get("whitelist", []))
        m.settings["whitelist"] = []
        self._p = mock.patch.object(m, "_save_settings", lambda s: None)
        self._p.start()

    def tearDown(self):
        self._p.stop()
        m.settings["whitelist"] = self._saved

    def test_add_normalises_a_url_to_its_host(self):
        r = self.client.post("/c2/whitelist", json={"domain": "https://www.Example.com/login?a=1"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["domain"], "example.com")
        self.assertEqual(m.settings["whitelist"], ["example.com"])

    def test_add_twice_does_not_duplicate_and_remove_undoes_it(self):
        self.client.post("/c2/whitelist", json={"domain": "example.com"})
        self.client.post("/c2/whitelist", json={"domain": "example.com"})
        self.assertEqual(m.settings["whitelist"], ["example.com"])
        r = self.client.post("/c2/whitelist", json={"domain": "example.com", "remove": True})
        self.assertEqual(r.json()["status"], "removed")
        self.assertEqual(m.settings["whitelist"], [])

    def test_a_shared_hosting_provider_is_refused(self):
        r = self.client.post("/c2/whitelist", json={"domain": "https://yolasite.com/"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(m.settings["whitelist"], [])

    def test_a_single_site_on_a_shared_host_is_allowed(self):
        r = self.client.post("/c2/whitelist", json={"domain": "https://mybakery.yolasite.com/"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(m.settings["whitelist"], ["mybakery.yolasite.com"])

    def test_garbage_is_rejected(self):
        self.assertEqual(self.client.post("/c2/whitelist", json={"domain": "  "}).status_code, 400)
        self.assertEqual(self.client.post("/c2/whitelist", json={"domain": "localhost"}).status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
