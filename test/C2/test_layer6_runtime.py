"""
test/C2/test_layer6_runtime.py
──────────────────────────────
Offline unit test for C2 Layer 6 (runtime behavioral) scoring — core/c2/layer6_runtime.py.
No browser required; feeds synthetic runtime-signal dicts to check_runtime.

Usage:
    python test/C2/test_layer6_runtime.py
"""
import asyncio
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c2.layer6_runtime import check_runtime  # noqa: E402

# (label, url, runtime, predicate(score) -> bool, why)
CASES = [
    ("empty", "https://x.com", None,
     lambda s: s == 0.0, "no runtime data -> 0"),
    ("keylogger-on-password", "https://evil.tk",
     {"kb_on_password": True, "page_host": "evil.tk", "exfil_hosts": []},
     lambda s: s >= 0.4, "password keylogger -> strong"),
    ("generic-keylistener", "https://shop.com",
     {"kb_listeners": 1, "page_host": "shop.com", "exfil_hosts": []},
     lambda s: 0 < s < 0.4, "one generic listener -> weak"),
    ("offorigin-exfil", "https://phish.tk",
     {"page_host": "phish.tk", "exfil_hosts": ["collector.ru"]},
     lambda s: s >= 0.4, "off-origin POST sink -> strong"),
    ("samesite-cdn-ignored", "https://shop.com",
     {"page_host": "shop.com", "exfil_hosts": ["cdn.shop.com"]},
     lambda s: s == 0.0, "same registrable host is not exfil"),
    ("full-bitb", "https://phish.tk",
     {"kb_on_password": True, "clipboard_listeners": 1, "drag_block": 2,
      "page_host": "phish.tk", "exfil_hosts": ["collector.ru"], "form_submit_external": True},
     lambda s: s >= 0.9, "all signals -> near max"),
]


async def run() -> int:
    failures = 0
    for label, url, rt, pred, why in CASES:
        res = await check_runtime(url, rt)
        s = res["score"]
        ok = pred(s)
        if not ok:
            failures += 1
        print(f"[{'PASS' if ok else 'FAIL'}] {label:24} score={s:<5} :: {why}")
        if not ok:
            print(f"        detail={res['detail']}")
    print("-" * 60)
    print(f"All {len(CASES)} L6 tests passed" if not failures else f"{failures} FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
