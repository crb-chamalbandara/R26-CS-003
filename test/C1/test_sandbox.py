"""
WebSentinel C1 — Sandbox verification script.

Run from the project root:
    python Test/C1/test_sandbox.py

What this tests:
  1. Static analysis on the synthetic test extension (should score ~55-60, verdict SUSPICIOUS)
  2. Dynamic sandbox on the same extension (should detect DATA_POST_TO_EXTERNAL,
     WEBSOCKET_TO_EXTERNAL from the background script's network calls)
  3. Full fused pipeline (static + dynamic combined)

A passing run looks like:
  - Static score >= 50  (sandbox trigger threshold met)
  - Sandbox executed = True
  - At least one dynamic signal detected
  - Final verdict: SUSPICIOUS or MALICIOUS
"""
import asyncio
import json
import os
import sys

# Allow running from project root without installing the package
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Canonical fixture lives under core/c1/ — the same copy /dev/simulate_click and
# the unit tests use. A second copy used to sit beside this file and silently
# drifted out of date, so this script reported a stale score (41) for an
# extension the real pipeline scored at 74. One fixture, one source of truth.
_EXT_DIR = os.path.join(_ROOT, "core", "c1", "test_malicious_ext")


def _sep(title: str) -> None:
    print(f"\n-- {title} {'-' * max(0, 55 - len(title))}")


async def main() -> None:
    from core.c1.sandbox import run_sandbox
    from core.c1.analyzer import analyze_extension

    if not os.path.isdir(_EXT_DIR):
        print(f"[ERROR] Test extension not found: {_EXT_DIR}")
        sys.exit(1)

    manifest_path = os.path.join(_EXT_DIR, "manifest.json")

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    # Concatenate every .js file, matching parse_crx_bytes() and /dev/simulate_click.
    # Reading background.js alone under-reports any extension whose content script
    # carries the interesting behaviour.
    _parts = []
    for _root, _dirs, _files in os.walk(_EXT_DIR):
        for _name in sorted(_files):
            if _name.lower().endswith(".js"):
                with open(os.path.join(_root, _name), encoding="utf-8", errors="ignore") as f:
                    _parts.append(f.read())
    source_code = "\n".join(_parts)

    manifest_str = json.dumps(manifest)

    # ── 1. Static-only (no extension_path) ─────────────────────────────────────
    _sep("Static analysis (no sandbox)")
    static_result = await analyze_extension(manifest_str, source_code, "test_malicious_ext")
    static_score = static_result["static"]["score"] * 100
    print(f"  Static score : {static_score:.1f} / 100")
    print(f"  ML prob      : {static_result['static']['ml_score']*100:.1f}%")
    print(f"  Verdict      : {static_result['verdict']}")
    print(f"  Flags        : {static_result['flags']}")

    if static_score < 50:
        print("\n  [WARN] Static score < 50 — sandbox would NOT trigger for a real intercept.")
        print("         Check model training or feature extraction.")
    else:
        print(f"\n  [OK] Static score >= 50 — sandbox threshold met.")

    # ── 2. Sandbox only ─────────────────────────────────────────────────────────
    _sep("Dynamic sandbox (20 s observation window)")
    print("  Starting sandbox browser… (a small Chromium window may appear briefly)")
    sandbox_result = await run_sandbox(_EXT_DIR, timeout_seconds=20)

    print(f"  Executed     : {sandbox_result['executed']}")
    print(f"  Dynamic score: {sandbox_result['score']} / 100")
    print(f"  Signals      : {sandbox_result['signals']}")
    print(f"  Net requests : {len(sandbox_result['network_requests'])}")
    print(f"  Page signals : {len(sandbox_result['page_signals'])}")
    if sandbox_result.get("error"):
        print(f"  [ERROR]      : {sandbox_result['error']}")

    if not sandbox_result["executed"]:
        print("\n  [FAIL] Sandbox did not execute. Check Playwright installation.")
    elif not sandbox_result["signals"]:
        print("\n  [WARN] Sandbox ran but no signals detected.")
        print("         The background script's network calls may have been blocked.")
    else:
        print(f"\n  [OK] Sandbox detected {len(sandbox_result['signals'])} signal(s).")

    # ── 3. Full fused pipeline ───────────────────────────────────────────────────
    _sep("Full pipeline (static + sandbox fused)")
    print("  Starting sandbox browser again… (another ~20 s)")
    full_result = await analyze_extension(manifest_str, source_code, "test_malicious_ext", _EXT_DIR)
    final_score = full_result["score"] * 100
    print(f"  Final score  : {final_score:.1f} / 100")
    print(f"  Verdict      : {full_result['verdict']}")
    print(f"  All flags    : {full_result['flags']}")
    print(f"  Detail       : {full_result['detail']}")

    # ── Summary ─────────────────────────────────────────────────────────────────
    _sep("Summary")
    ok = sandbox_result["executed"] and len(sandbox_result["signals"]) > 0
    print(f"  Static ML    : {'OK' if static_score >= 50 else 'LOW (check model)'}")
    print(f"  Sandbox ran  : {'OK' if sandbox_result['executed'] else 'FAILED'}")
    print(f"  Signals found: {'OK — ' + ', '.join(sandbox_result['signals']) if sandbox_result['signals'] else 'NONE (check ctx.on fix)'}")
    print(f"  Score fusion : {'OK' if full_result['dynamic']['executed'] else 'SKIPPED (sandbox did not run)'}")
    print()
    print(f"  Overall: {'PASS' if ok else 'FAIL — review warnings above'}")


if __name__ == "__main__":
    asyncio.run(main())
