"""
scripts/evaluate_c2.py
──────────────────────
C2 evaluation / benchmark harness.

Static mode (no browser): runs the DOM/URL layers (L1 BitB, L2 URL, L4 Form) over the
labeled Mendeley corpus (HTML snapshots + index.sql labels), computes per-layer ROC/AUC and
PR, the fused risk score, and the confusion matrix / precision / recall / F1 at the current
verdict cutoffs. Writes notebooks/C2/eval/metrics.json plus PNG plots.

This is the measurement foundation the model + fusion tuning build on.

Usage:
    python scripts/evaluate_c2.py                 # default 1500 pages/class
    python scripts/evaluate_c2.py --per-class 4000
    python scripts/evaluate_c2.py --no-plots

Layers needing a live browser (L3 visual, L5 reputation, L6 runtime) are scored 0 in static
mode and excluded from per-layer AUC; the live harness (added later) covers them.
"""
import argparse
import asyncio
import io
import json
import os
import re
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DATASET_ZIP = REPO_ROOT / "notebooks" / "C2" / "Dataset" / "n96ncsr5g4-1.zip"
EVAL_DIR    = REPO_ROOT / "notebooks" / "C2" / "eval"

# Current production fusion config (mirror of core/main.py analyze()).
WEIGHTS    = {"L1": 0.15, "L2": 0.30, "L3": 0.20, "L4": 0.15, "L5": 0.20}
T_SUSPECT  = 30
T_PHISH    = 60

try:
    import numpy as np
    from sklearn.metrics import (roc_auc_score, average_precision_score,
                                 roc_curve, precision_recall_curve,
                                 confusion_matrix, classification_report,
                                 precision_score, recall_score, f1_score)
except ImportError as e:
    sys.exit(f"Missing dependency: {e}\nRun: pip install scikit-learn numpy")

from core.c2.layer1_bitb import check_bitb
from core.c2.layer2_url  import check_url
from core.c2.layer4_form import check_form


# ── Corpus loading ────────────────────────────────────────────────────────────
def parse_index(sql_text: str) -> dict:
    """website-filename -> (url, label) from the index.sql INSERT rows."""
    out = {}
    row = re.compile(r"\(\s*\d+\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*([01])\s*,")
    for m in row.finditer(sql_text):
        url, website, label = m.group(1), m.group(2), int(m.group(3))
        if website:
            out[website] = (url, label)
    return out


def load_corpus(per_class: int):
    """Return a balanced list of (url, html, label) sampled from the nested zips."""
    if not DATASET_ZIP.exists():
        sys.exit(f"Dataset not found: {DATASET_ZIP}")
    outer = zipfile.ZipFile(DATASET_ZIP)
    index = parse_index(outer.read("n96ncsr5g4-1/index.sql").decode("utf-8", "replace"))
    print(f"[corpus] index.sql: {len(index):,} labeled records")

    counts = {0: 0, 1: 0}
    samples = []
    parts = [n for n in outer.namelist() if n.endswith(".zip")]
    for part in parts:
        if counts[0] >= per_class and counts[1] >= per_class:
            break
        inner = zipfile.ZipFile(io.BytesIO(outer.read(part)))
        for name in inner.namelist():
            if not name.lower().endswith((".html", ".htm")):
                continue
            website = os.path.basename(name)
            meta = index.get(website)
            if not meta:
                continue
            url, label = meta
            if counts[label] >= per_class:
                continue
            try:
                html = inner.read(name).decode("utf-8", "replace")
            except Exception:
                continue
            samples.append((url, html, label))
            counts[label] += 1
            if counts[0] >= per_class and counts[1] >= per_class:
                break
    print(f"[corpus] sampled legit={counts[0]:,}  phishing={counts[1]:,}")
    return samples


# ── Scoring ───────────────────────────────────────────────────────────────────
async def score_corpus(samples):
    """Run static layers per page; return dict of np arrays."""
    n = len(samples)
    L1 = np.zeros(n); L2 = np.zeros(n); L4 = np.zeros(n); y = np.zeros(n, dtype=int)
    for i, (url, html, label) in enumerate(samples):
        y[i] = label
        try:    L1[i] = (await check_bitb(url, html))["score"]
        except Exception: pass
        try:    L2[i] = (await check_url(url))["score"]
        except Exception: pass
        try:    L4[i] = (await check_form(url, html))["score"]
        except Exception: pass
        if (i + 1) % 500 == 0:
            print(f"[score] {i+1}/{n}")
    fused = (WEIGHTS["L1"] * L1 + WEIGHTS["L2"] * L2 + WEIGHTS["L4"] * L4) * 100
    return {"L1": L1, "L2": L2, "L4": L4, "fused": fused, "y": y}


# ── Metrics ───────────────────────────────────────────────────────────────────
def per_layer_metrics(scores, y):
    out = {}
    for layer in ("L1", "L2", "L4"):
        s = scores[layer]
        try:
            out[layer] = {
                "auc": round(float(roc_auc_score(y, s)), 4),
                "ap":  round(float(average_precision_score(y, s)), 4),
            }
        except Exception:
            out[layer] = {"auc": None, "ap": None}
    return out


def fused_metrics(fused, y):
    auc = round(float(roc_auc_score(y, fused)), 4)
    rep = {}
    for name, thr in (("suspicious", T_SUSPECT), ("phishing", T_PHISH)):
        pred = (fused >= thr).astype(int)
        rep[name] = {
            "threshold": thr,
            "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
            "recall":    round(float(recall_score(y, pred, zero_division=0)), 4),
            "f1":        round(float(f1_score(y, pred, zero_division=0)), 4),
            "confusion": confusion_matrix(y, pred).tolist(),  # [[TN,FP],[FN,TP]]
        }
    return {"auc": auc, "operating_points": rep}


# ── Plots ─────────────────────────────────────────────────────────────────────
def write_plots(scores, y, outdir: Path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[plots] matplotlib not installed — skipping (pip install matplotlib)")
        return []
    written = []

    # ROC overlay
    plt.figure(figsize=(6, 5))
    for layer in ("L1", "L2", "L4", "fused"):
        s = scores[layer]
        fpr, tpr, _ = roc_curve(y, s)
        plt.plot(fpr, tpr, label=f"{layer} (AUC={roc_auc_score(y, s):.3f})")
    plt.plot([0, 1], [0, 1], "k--", lw=0.7)
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title("C2 ROC — per layer & fused"); plt.legend(loc="lower right")
    p = outdir / "roc.png"; plt.tight_layout(); plt.savefig(p, dpi=120); plt.close(); written.append(str(p))

    # Confusion matrix at phishing cutoff
    pred = (scores["fused"] >= T_PHISH).astype(int)
    cm = confusion_matrix(y, pred)
    plt.figure(figsize=(4, 4))
    plt.imshow(cm, cmap="Blues")
    for (r, c), v in np.ndenumerate(cm):
        plt.text(c, r, str(v), ha="center", va="center")
    plt.xticks([0, 1], ["Legit", "Phish"]); plt.yticks([0, 1], ["Legit", "Phish"])
    plt.xlabel("Predicted"); plt.ylabel("Actual")
    plt.title(f"Fused confusion @ risk>={T_PHISH}")
    p = outdir / "confusion.png"; plt.tight_layout(); plt.savefig(p, dpi=120); plt.close(); written.append(str(p))
    return written


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=1500)
    ap.add_argument("--no-plots", action="store_true")
    args = ap.parse_args()

    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    samples = load_corpus(args.per_class)
    if not samples:
        sys.exit("No samples loaded.")

    scores = asyncio.run(score_corpus(samples))
    y = scores["y"]

    report = {
        "n_samples": int(len(y)),
        "n_phishing": int(y.sum()),
        "n_legit": int((y == 0).sum()),
        "weights": WEIGHTS,
        "per_layer": per_layer_metrics(scores, y),
        "fused": fused_metrics(scores["fused"], y),
        "note": "static mode — L3/L5/L6 scored 0 (need live browser)",
    }

    out_json = EVAL_DIR / "metrics.json"
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    plots = [] if args.no_plots else write_plots(scores, y, EVAL_DIR)

    print("\n========== C2 STATIC EVALUATION ==========")
    print(f"samples: {report['n_samples']}  (phish {report['n_phishing']} / legit {report['n_legit']})")
    print("per-layer AUC:", {k: v["auc"] for k, v in report["per_layer"].items()})
    print(f"fused AUC: {report['fused']['auc']}")
    for op, m in report["fused"]["operating_points"].items():
        print(f"  @{op}(>={m['threshold']}): P={m['precision']} R={m['recall']} F1={m['f1']} cm={m['confusion']}")
    print(f"\nreport -> {out_json}")
    for p in plots:
        print(f"plot   -> {p}")


if __name__ == "__main__":
    main()
