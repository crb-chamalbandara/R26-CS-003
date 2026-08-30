"""
scripts/capture_fusion_vectors.py
─────────────────────────────────
Renders a labeled sample of pages in a HEADLESS browser (with the L6 runtime hook
installed) and records the full six-layer C2 score vector per page. The output CSV
(L1..L6,label) is the training set for scripts/tune_fusion.py — it's the only way to
get real L3 (visual) and L6 (runtime) scores, which need a live page.

Corpus: a balanced sample of the Mendeley HTML snapshots (real phishing/legit with real
URLs) via scripts/evaluate_c2.load_corpus, plus the local BitB kit samples as extra
BitB-specific positives.

L5 (reputation) is recorded 0 here (no network/key); tune_fusion accounts for that.

Usage:
    python scripts/capture_fusion_vectors.py --per-class 200
    python scripts/capture_fusion_vectors.py --per-class 400 --out notebooks/C2/eval/fusion_vectors.csv
"""
import argparse
import asyncio
import csv
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.c2.layer1_bitb    import check_bitb
from core.c2.layer2_url     import check_url
from core.c2.layer3_visual  import check_visual
from core.c2.layer4_form    import check_form
from core.c2.layer6_runtime import check_runtime
from core.playwright_session import _RUNTIME_HOOK
from scripts.evaluate_c2 import load_corpus

OUT_DEFAULT = REPO_ROOT / "notebooks" / "C2" / "eval" / "fusion_vectors.csv"
BITB_DIR    = REPO_ROOT / "test" / "C2"


def bitb_samples():
    """Local BitB positives: kit index.html files + graded anomaly pages."""
    files = []
    for p in (BITB_DIR / "bitb_samples").glob("*/index.html"):
        files.append(("file:///" + str(p).replace("\\", "/"), None, 1))
    for name in ("bitb_anomaly_50.html", "bitb_anomaly_75.html",
                 "bitb_anomaly_100.html", "bitb_test.html"):
        p = BITB_DIR / name
        if p.exists():
            files.append(("file:///" + str(p).replace("\\", "/"), None, 1))
    return files


async def score_page(page, url, html, label):
    """Render one page headless, collect all six layer scores. Resilient to pages that
    redirect on load (common in phishing kits): the DOM is grabbed immediately, and the
    runtime/screenshot steps are best-effort so a destroyed context never drops the row."""
    score_url = url if html is not None else "http://login-verify-secure.example/account"
    try:
        if html is not None:          # Mendeley snapshot
            await page.set_content(html, wait_until="commit", timeout=6000)
        else:                          # local kit file → navigate so script.js loads
            await page.goto(url, wait_until="commit", timeout=6000)
    except Exception:
        return None

    dom = ""
    try:
        dom = await page.content()     # grab DOM ASAP, before any redirect fires
    except Exception:
        return None
    if not dom:
        return None

    try:
        await page.wait_for_timeout(200)  # let inline scripts register handlers
    except Exception:
        pass
    try:
        rt = await page.evaluate("() => window.__ws_runtime || null") or {}
    except Exception:
        rt = {}
    shot = ""
    try:
        import base64
        data = await page.screenshot(type="jpeg", quality=70, full_page=False)
        shot = base64.b64encode(data).decode()
    except Exception:
        shot = ""

    L1 = (await check_bitb(score_url, dom)).get("score", 0.0)
    L2 = (await check_url(score_url)).get("score", 0.0)
    L3 = (await check_visual(score_url, shot)).get("score", 0.0)
    L4 = (await check_form(score_url, dom)).get("score", 0.0)
    L5 = 0.0  # reputation needs network/key — left 0 for offline capture
    L6 = (await check_runtime(score_url, rt)).get("score", 0.0)
    return [L1, L2, L3, L4, L5, L6, label]


def _progress(done, total, kept, pos, width=34):
    """Live in-place progress bar (no external deps)."""
    frac = done / total if total else 1.0
    filled = int(width * frac)
    bar = "#" * filled + "-" * (width - filled)
    sys.stdout.write(
        f"\r[capture] [{bar}] {done}/{total} ({frac*100:5.1f}%)  "
        f"kept={kept} phish={pos} legit={kept - pos}   ")
    sys.stdout.flush()


PER_PAGE_BUDGET = 12  # seconds; pages that exceed this (e.g. anti-debug JS loops) are skipped


async def _new_page(ctx):
    page = await ctx.new_page()
    page.set_default_timeout(6000)
    # Auto-dismiss alert/confirm/prompt so a modal dialog can't block the renderer.
    page.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))
    return page


async def run(samples, out_path):
    from playwright.async_api import async_playwright
    rows = []
    total = len(samples)
    kept = pos = skipped = 0
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx = await browser.new_context(viewport={"width": 1280, "height": 800})
        await ctx.add_init_script(script=_RUNTIME_HOOK)
        page = await _new_page(ctx)
        for i, (url, html, label) in enumerate(samples):
            recreate = False
            try:
                row = await asyncio.wait_for(
                    score_page(page, url, html, label), timeout=PER_PAGE_BUDGET)
            except asyncio.TimeoutError:
                row, recreate = None, True   # renderer wedged → rebuild the page
            except Exception:
                row = None
            if row:
                rows.append(row); kept += 1
                if row[-1] == 1:
                    pos += 1
            else:
                skipped += 1
            if recreate:
                try: await page.close()
                except Exception: pass
                try: page = await _new_page(ctx)
                except Exception: pass
            _progress(i + 1, total, kept, pos)
        sys.stdout.write("\n")
        await browser.close()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["L1", "L2", "L3", "L4", "L5", "L6", "label"])
        w.writerows(rows)
    pos = sum(1 for r in rows if r[-1] == 1)
    print(f"[capture] wrote {len(rows)} vectors ({pos} phish / {len(rows)-pos} legit; "
          f"{skipped} skipped) -> {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=200)
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    args = ap.parse_args()

    mendeley = load_corpus(args.per_class)              # (url, html, label)
    samples = mendeley + bitb_samples()
    print(f"[capture] {len(samples)} pages to render "
          f"({len(mendeley)} Mendeley + {len(samples)-len(mendeley)} BitB kits)")
    asyncio.run(run(samples, args.out))


if __name__ == "__main__":
    main()
