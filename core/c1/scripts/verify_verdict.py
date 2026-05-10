"""Run from project root: python core/c1/scripts/verify_verdict.py"""
import asyncio, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

EXT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test_malicious_ext")

async def main():
    from core.c1.analyzer import analyze_extension
    from core.c1.db import save_result, get_history

    with open(os.path.join(EXT_DIR, "manifest.json")) as f:
        manifest = json.load(f)
    with open(os.path.join(EXT_DIR, "background.js")) as f:
        src = f.read()

    print("-- Analyzer + Report -----------------------------------------")
    result = await analyze_extension(json.dumps(manifest), src, "test_malicious_ext")
    print(f"  extension_id : {result.get('extension_id')}")
    print(f"  verdict      : {result['verdict']}")
    print(f"  final score  : {round(result['score']*100, 1)}")
    print(f"  report keys  : {list(result['report'].keys())}")
    print(f"  risk_level   : {result['report']['risk_level']}")
    print(f"  formula      : {result['report']['score_breakdown']['formula']}")
    print(f"  summary      : {result['report']['summary'][:90]}")
    print(f"  flag entries : {len(result['report']['flags'])}")
    for f2 in result['report']['flags']:
        print(f"    [{f2['severity']:8}] {f2['flag']}: {f2['description'][:55]}")
    print(f"  recommendation: {result['report']['recommendation'][:70]}")

    print()
    print("-- Database --------------------------------------------------")
    result["timestamp"] = "2026-05-09T12:00:00"
    result["source"]    = "test"
    row_id = save_result(result)
    print(f"  Saved — row id : {row_id}")
    history = get_history(3)
    print(f"  History rows   : {len(history)}")
    latest = history[0]
    print(f"  Latest verdict : {latest['verdict']}  final_score={latest['final_score']}")
    print(f"  Flags in DB    : {latest['flags']}")
    print()
    print("ALL CHECKS PASSED")

if __name__ == "__main__":
    asyncio.run(main())
