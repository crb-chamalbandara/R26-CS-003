"""
C2 Live Analysis tests -- reasons, per-layer progress events, whitelist action.
Run from project root:  python test/C2/test_c2_live.py
"""
import asyncio
import json
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


class TestInlineReports(unittest.TestCase):
    """Reports and exports must be viewable in the app, not forced to a Save dialog."""

    def setUp(self):
        from fastapi.testclient import TestClient
        self.client = TestClient(m.app)
        self.alert = {"id": 7, "url": "https://victim.example/login", "verdict": "PHISHING", "risk_score": 80,
                      "timestamp": "2026-10-09T10:00:00", "verified": False, "layers": [], "fusion": {}}
        self._p = [mock.patch.object(m, "_get_c2_alert_or_404", lambda i: self.alert),
                   mock.patch.object(m.c2_alert_store, "list_alerts", lambda *a, **k: [self.alert])]
        for p in self._p: p.start()

    def tearDown(self):
        for p in self._p: p.stop()

    def test_default_is_still_a_download(self):
        for path in ("/alerts/7/report.html", "/alerts/7/report.json",
                     "/alerts/export.csv", "/alerts/export.json", "/alerts/export.siem"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, path)
            self.assertIn("attachment", r.headers.get("content-disposition", ""), path)

    def test_inline_omits_the_attachment_header(self):
        for path in ("/alerts/7/report.html", "/alerts/7/report.json",
                     "/alerts/export.csv", "/alerts/export.json", "/alerts/export.siem"):
            r = self.client.get(path + "?inline=1")
            self.assertEqual(r.status_code, 200, path)
            self.assertNotIn("content-disposition", r.headers, path)
            self.assertEqual(r.headers.get("x-content-type-options"), "nosniff")

    def test_inline_html_is_locked_down_and_keeps_its_content(self):
        r = self.client.get("/alerts/7/report.html?inline=1")
        self.assertIn("default-src 'none'", r.headers["content-security-policy"])
        self.assertIn("victim.example", r.text)
        self.assertTrue(r.headers["content-type"].startswith("text/html"))

    def test_inline_json_is_valid_json(self):
        r = self.client.get("/alerts/7/report.json?inline=1")
        self.assertEqual(json.loads(r.text)["id"], 7)


class TestPipelineData(unittest.TestCase):

    def test_layer_events_carry_the_time_each_layer_took(self):
        sent = []
        async def fake_broadcast(d): sent.append(d)
        async def go():
            m._c2_live_ctx.set({"tab_id": 1, "url": "u"})
            await m._c2_emit_layer("L1", "BitB", {"score": .5, "detail": ""}, 42)
        with mock.patch.object(m, "_broadcast", fake_broadcast):
            asyncio.run(go())
        self.assertEqual(sent[0]["layer"]["ms"], 42)

    def test_analyze_reports_timings_fusion_and_thresholds(self):
        async def go():
            m._c2_live_ctx.set(None)
            return await m.analyze(m.AnalyzeReq(url="https://victim.example/login", dom="<html></html>"))
        with mock.patch.object(m, "_store_c2_alert", lambda a: {}), mock.patch.object(m, "is_verified", lambda u: False):
            r = asyncio.run(go())
        self.assertEqual(set(r["timings"]["layers"]), {l["id"] for l in r["layers"]})
        self.assertTrue(all(isinstance(v, int) for v in r["timings"]["layers"].values()))
        self.assertIn("fusion_ms", r["timings"])
        self.assertIn(r["fusion"]["method"], ("weighted_sum", "meta_classifier"))
        self.assertEqual(set(r["thresholds"]), {"suspicious", "phishing", "warn", "block", "interstitial"})

    def test_response_action_follows_the_thresholds(self):
        s = {"interstitial_enabled": True, "warn_threshold": 30, "block_threshold": 60}
        with mock.patch.dict(m.settings, s):
            self.assertEqual(m._c2_response_action(10), "none")
            self.assertEqual(m._c2_response_action(30), "warn")
            self.assertEqual(m._c2_response_action(59.9), "warn")
            self.assertEqual(m._c2_response_action(60), "block")
        with mock.patch.dict(m.settings, {"interstitial_enabled": False}):
            self.assertEqual(m._c2_response_action(99), "off")


class _FakePage:
    def __init__(self, url, closed=False): self.url, self._closed = url, closed
    def is_closed(self): return self._closed


class _FakeSession:
    """Just enough of PlaywrightSession for the re-analyze endpoint."""
    def __init__(self, running=True, pages=None, active=None):
        self.is_running, self.pages, self.active = running, pages or {}, active
        self.forgot, self.navigated = [], []
    def page_for_tab(self, tab_id): return self.pages.get(tab_id)
    def active_page(self): return self.active
    def forget_url(self, page): self.forgot.append(page)
    async def navigate_page(self, page, url): self.navigated.append((page, url))
    def tab_id(self, page): return next((k for k, v in self.pages.items() if v is page), 0)


class TestReanalyze(unittest.TestCase):

    def _call(self, sess, **body):
        calls = []
        async def fake_handler(url, page=None): calls.append((url, page))
        async def go():
            res = await m.c2_reanalyze(m.ReanalyzeReq(**body))
            await asyncio.sleep(0.05)               # let the background task run
            return res
        with mock.patch.object(m, "pw_session", sess), mock.patch.object(m, "_pw_nav_handler", fake_handler):
            return asyncio.run(go()), calls

    def test_a_tab_still_on_the_page_is_analysed_in_place_without_navigating(self):
        page = _FakePage("https://victim.example/login")
        sess = _FakeSession(pages={3: page})
        res, calls = self._call(sess, url="https://victim.example/login/", tab_id=3)
        self.assertEqual(res["mode"], "current")
        self.assertEqual(calls, [("https://victim.example/login", page)])
        self.assertEqual(sess.navigated, [])

    def test_a_tab_that_moved_on_is_taken_back_and_its_url_forgotten_first(self):
        page = _FakePage("https://elsewhere.example/")
        sess = _FakeSession(pages={3: page})
        res, calls = self._call(sess, url="https://victim.example/login", tab_id=3)
        self.assertEqual(res["mode"], "navigated")
        self.assertEqual(sess.forgot, [page])
        self.assertEqual(sess.navigated, [(page, "https://victim.example/login")])
        self.assertEqual(calls, [])

    def test_a_closed_tab_falls_back_to_the_active_tab(self):
        active = _FakePage("https://other.example/")
        sess = _FakeSession(pages={}, active=active)
        res, _ = self._call(sess, url="https://victim.example/login", tab_id=9)
        self.assertEqual(res["mode"], "reopened")
        self.assertEqual(sess.navigated, [(active, "https://victim.example/login")])

    def test_errors_are_explained(self):
        from fastapi import HTTPException
        for sess, body, code in [
            (_FakeSession(running=False), {"url": "https://x.test/"}, 400),
            (_FakeSession(), {"url": "  "}, 400),
            (_FakeSession(pages={}, active=None), {"url": "https://x.test/", "tab_id": 1}, 409),
        ]:
            with self.assertRaises(HTTPException) as cm:
                self._call(sess, **body)
            self.assertEqual(cm.exception.status_code, code)
            self.assertTrue(cm.exception.detail)

    def test_same_url_comparison_ignores_trailing_slash_and_fragment(self):
        self.assertTrue(m._c2_same_url("https://a.test/x/", "https://a.test/x#top"))
        self.assertFalse(m._c2_same_url("https://a.test/x", "https://a.test/y"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
