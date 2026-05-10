"""
End-to-end validation of the C3 dual-model pipeline.

Loads both trained models and scores every session in
data/c3_web_bot_sessions.csv through the full detection pipeline:

    Isolation Forest (4 timing features)
  + RF Classifier   (10 HTTP behavior features)
  + Heuristic rules (available features from server logs)
  → Risk Fusion
  → Verdict (SAFE / SUSPICIOUS / BEACON)

Reports per-model AND combined metrics so the contribution of each
signal layer is clearly visible.

NOTE on browser-context features:
  avg_idle_time_ms, user_active_ratio, background_tab_ratio, and
  extension_origin_ratio are absent from server-side logs and default
  to 0.  Heuristic rules that rely on these features will NOT fire —
  this is expected; they activate in live CDP sessions only.
"""
from __future__ import annotations

import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)

REPO_ROOT     = Path(__file__).resolve().parent.parent
IF_MODEL_PATH = REPO_ROOT / "models" / "c3_isolation_forest.pkl"
RF_MODEL_PATH = REPO_ROOT / "models" / "c3_rf_classifier.pkl"
DATA_PATH     = REPO_ROOT / "data" / "c3_web_bot_sessions.csv"

IF_FEATURES = ["iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms"]

RF_FEATURES = [
    "iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms",
    "requests_per_hour", "payload_size_mean", "payload_size_std",
    "http_post_ratio", "url_path_entropy", "request_burst_count",
]

SEP = "=" * 68


# ── Model loading ──────────────────────────────────────────────────────────────

def load_if_model(path: Path) -> tuple:
    """Load Isolation Forest payload → (model, cal_low, cal_high)."""
    with open(path, "rb") as f:
        p = pickle.load(f)
    if isinstance(p, dict):
        model = p.get("model") or p.get("estimator") or p.get("iforest")
        low   = float(p.get("calibration_low") or p.get("low") or p.get("p5") or 0)
        high  = float(p.get("calibration_high") or p.get("high") or p.get("p95") or 1)
    elif isinstance(p, (list, tuple)) and len(p) == 3:
        model, low, high = p
        low, high = float(low), float(high)
    else:
        model, low, high = p, 0.0, 1.0
    return model, low, high


def load_rf_model(path: Path) -> tuple:
    """Load RF payload → (model, feature_names, threshold)."""
    with open(path, "rb") as f:
        p = pickle.load(f)
    if isinstance(p, dict):
        model   = p["model"]
        feats   = p.get("feature_names", RF_FEATURES)
        thresh  = float(p.get("threshold", 0.5))
    else:
        model, feats, thresh = p, RF_FEATURES, 0.5
    return model, feats, thresh


# ── Scoring helpers ────────────────────────────────────────────────────────────

def _if_normalize(raw: float, low: float, high: float) -> float:
    if high == low:
        return 0.0
    scaled = (raw - low) / (high - low)
    return round(1.0 - max(0.0, min(1.0, scaled)), 6)


def score_if(model, low: float, high: float, row: dict) -> float | None:
    """Return normalized anomaly score (0–1) or None if features all-zero."""
    values = [float(row.get(f, 0.0)) for f in IF_FEATURES]
    if sum(1 for v in values if v != 0.0) < 1:
        return None
    X = np.array([values], dtype=float)
    raw = float(model.score_samples(X)[0])
    return _if_normalize(raw, low, high)


def score_rf(model, feature_names: list[str], row: dict) -> float:
    """Return bot probability (0–1)."""
    values = [float(row.get(f, 0.0)) for f in feature_names]
    X = np.array([values], dtype=float)
    return float(model.predict_proba(X)[0][1])


def score_heuristic(row: dict) -> float:
    """
    Rule-based score mirroring analyzer._heuristic_score().
    Browser-context features (user_active_ratio, avg_idle_time_ms,
    background_tab_ratio, extension_origin_ratio) are absent from
    server logs → default 0 → those rules do not fire here.
    """
    score = 0.0
    iat_cv    = float(row.get("iat_cv", 1.0))
    iat_mean  = float(row.get("iat_mean_ms", 0.0))
    uar       = float(row.get("user_active_ratio", 1.0))   # always 1.0 (not in CSV)
    bg        = float(row.get("background_tab_ratio", 0.0))
    ext       = float(row.get("extension_origin_ratio", 0.0))
    path_ent  = float(row.get("url_path_entropy", 1.0))
    avg_idle  = float(row.get("avg_idle_time_ms", 0.0))

    if iat_cv < 0.05 and iat_mean > 0 and uar < 0.50:
        score += 0.30
    if uar < 0.05 and bg < 0.50 and avg_idle > 30_000:
        score += 0.25
    if bg > 0.80:
        score += 0.08 if ext != 0.0 else 0.20
    if ext > 0.0:
        score += 0.15
    if path_ent < 0.50 and iat_cv < 0.10 and iat_mean > 0 and uar < 0.50:
        score += 0.10

    return min(1.0, score)


def fuse(anomaly: float | None,
         browser: float | None,
         heuristic: float) -> float:
    """
    Inline fusion matching risk_fusion.C3RiskFusion.fuse()
    (reputation=None since no IP data in server logs).
    """
    has_a = anomaly is not None
    has_b = browser is not None

    if has_a and has_b:
        weights = {"anomaly": 0.45, "browser_anomaly": 0.20, "heuristic": 0.35}
    elif has_a:
        weights = {"anomaly": 0.65, "heuristic": 0.35}
    elif has_b:
        weights = {"browser_anomaly": 0.65, "heuristic": 0.35}
    else:
        weights = {"heuristic": 1.0}

    score = 0.0
    if has_a:
        score += float(anomaly) * weights.get("anomaly", 0.0)
    if has_b:
        score += float(browser) * weights.get("browser_anomaly", 0.0)
    score += heuristic * weights.get("heuristic", 0.0)

    # Safety guard: anomaly alone cannot reach BEACON without heuristic confirmation
    if score >= 0.6 and heuristic < 0.10:
        score = min(score, 0.59)

    return max(0.0, min(1.0, float(score)))


def verdict(score: float) -> str:
    return "BEACON" if score >= 0.6 else "SUSPICIOUS" if score >= 0.3 else "SAFE"


# ── Report helpers ─────────────────────────────────────────────────────────────

def _metrics(y_true, y_pred, proba=None, name="") -> dict:
    acc  = float((np.array(y_pred) == np.array(y_true)).mean())
    mf1  = float(f1_score(y_true, y_pred, average="macro"))
    auc  = float(roc_auc_score(y_true, proba)) if proba is not None else float("nan")
    cm   = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = (cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]) if cm.shape == (2,2) else (0,0,0,0)
    fp_r = fp / (tn + fp) * 100 if (tn + fp) > 0 else 0.0
    rec  = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0.0
    return {"acc": acc, "mf1": mf1, "auc": auc, "fp_rate": fp_r,
            "recall": rec, "tn": tn, "fp": fp, "fn": fn, "tp": tp}


def _print_model_block(name: str, m: dict, show_auc: bool = True) -> None:
    auc_str = f"{m['auc']:.4f}" if not (m['auc'] != m['auc']) else "n/a"
    print(f"  {name}")
    print(f"    Accuracy : {m['acc']*100:.1f}%   Macro-F1 : {m['mf1']:.4f}", end="")
    if show_auc:
        print(f"   ROC-AUC : {auc_str}")
    else:
        print()
    print(f"    FP rate  : {m['fp_rate']:.1f}%  (benign flagged as bot/beacon)")
    print(f"    Recall   : {m['recall']:.1f}%  (bots correctly detected)")
    print(f"    Confusion: TN={m['tn']}  FP={m['fp']}  FN={m['fn']}  TP={m['tp']}")
    print()


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print()
    print(SEP)
    print("  C3 Dual-Model Pipeline — End-to-End Validation")
    print(SEP)

    # Check inputs
    for p, label in [(IF_MODEL_PATH, "IF model"), (RF_MODEL_PATH, "RF model"),
                     (DATA_PATH, "session CSV")]:
        if not p.exists():
            sys.exit(f"\nMissing {label}: {p}\n"
                     "Run the training scripts first.")

    # Load models
    print("\nLoading models ...")
    if_model, if_low, if_high = load_if_model(IF_MODEL_PATH)
    rf_model, rf_feats, rf_thresh = load_rf_model(RF_MODEL_PATH)
    print(f"  IF  model : {IF_MODEL_PATH.name}  (cal_low={if_low:.4f}  cal_high={if_high:.4f})")
    print(f"  RF  model : {RF_MODEL_PATH.name}  (threshold={rf_thresh:.2f}  features={len(rf_feats)})")

    # Load data
    df = pd.read_csv(DATA_PATH)
    df["label"] = df["label"].astype(int)
    n_total  = len(df)
    n_human  = (df["label"] == 0).sum()
    n_bot    = (df["label"] == 1).sum()
    print(f"\nSessions   : {n_total}  |  Human: {n_human}  Bot: {n_bot}")

    # Score every session
    y_true       = []
    if_scores    = []
    rf_scores    = []
    h_scores     = []
    fused_scores = []
    if_valid     = []   # rows where IF could score (non-zero timing features)

    for _, row in df.iterrows():
        row_dict = row.to_dict()
        y_true.append(int(row["label"]))

        s_if   = score_if(if_model, if_low, if_high, row_dict)
        s_rf   = score_rf(rf_model, rf_feats, row_dict)
        s_h    = score_heuristic(row_dict)
        s_fuse = fuse(s_if, s_rf, s_h)

        if_scores.append(s_if if s_if is not None else 0.0)
        if_valid.append(s_if is not None)
        rf_scores.append(s_rf)
        h_scores.append(s_h)
        fused_scores.append(s_fuse)

    y_true       = np.array(y_true)
    if_scores    = np.array(if_scores)
    rf_scores    = np.array(rf_scores)
    h_scores     = np.array(h_scores)
    fused_scores = np.array(fused_scores)

    # ── Per-model metrics ─────────────────────────────────────────────────────
    print()
    print(SEP)
    print("  Per-Model Detection Metrics  (threshold at 0.5 unless noted)")
    print(SEP)
    print()

    # IF: flag as bot if score >= 0.5
    if_pred = (if_scores >= 0.5).astype(int)
    m_if = _metrics(y_true, if_pred, if_scores, "IF")
    _print_model_block(
        f"Model 1 — Isolation Forest (4 timing features, threshold=0.50)", m_if
    )

    # RF: flag as bot if prob >= threshold
    rf_pred = (rf_scores >= rf_thresh).astype(int)
    m_rf = _metrics(y_true, rf_pred, rf_scores, "RF")
    _print_model_block(
        f"Model 2 — RF Classifier (10 features, threshold={rf_thresh:.2f})", m_rf
    )

    # Heuristic alone
    h_pred = (h_scores >= 0.3).astype(int)
    m_h = _metrics(y_true, h_pred, h_scores, "Heuristic")
    _print_model_block("Heuristic rules (threshold=0.30)", m_h, show_auc=True)

    # Fused: BEACON/SUSPICIOUS = 1, SAFE = 0
    fused_pred = (fused_scores >= 0.3).astype(int)   # SUSPICIOUS or worse = bot
    fused_pred_strict = (fused_scores >= 0.6).astype(int)  # BEACON only
    m_fused_any    = _metrics(y_true, fused_pred,        fused_scores)
    m_fused_strict = _metrics(y_true, fused_pred_strict, fused_scores)
    _print_model_block(
        "FUSED — IF + RF + Heuristic  (SUSPICIOUS or BEACON = bot, score>=0.30)", m_fused_any
    )
    _print_model_block(
        "FUSED — BEACON only  (score >= 0.60)", m_fused_strict
    )

    # ── Score distribution ────────────────────────────────────────────────────
    print(SEP)
    print("  Score Distribution by Class")
    print(SEP)
    print()
    for name, scores in [
        ("IF  score (timing IF)", if_scores),
        ("RF  score (HTTP RF)  ", rf_scores),
        ("Heuristic score      ", h_scores),
        ("Fused score          ", fused_scores),
    ]:
        h_mean = scores[y_true == 0].mean()
        b_mean = scores[y_true == 1].mean()
        h_max  = scores[y_true == 0].max()
        b_min  = scores[y_true == 1].min()
        sep_quality = "GOOD" if b_mean > h_mean + 0.15 else "weak"
        print(f"  {name}  human_mean={h_mean:.3f}  bot_mean={b_mean:.3f}  "
              f"[{sep_quality}]")
    print()

    # ── Verdict distribution ──────────────────────────────────────────────────
    print(SEP)
    print("  Fused Verdict Distribution")
    print(SEP)
    verdicts = [verdict(s) for s in fused_scores]
    for v_label in ["BEACON", "SUSPICIOUS", "SAFE"]:
        human_count = sum(1 for i, v in enumerate(verdicts) if v == v_label and y_true[i] == 0)
        bot_count   = sum(1 for i, v in enumerate(verdicts) if v == v_label and y_true[i] == 1)
        print(f"  {v_label:<12}  human={human_count:3d}  bot={bot_count:3d}")
    print()

    # ── IF coverage ───────────────────────────────────────────────────────────
    valid_count = sum(if_valid)
    print(f"  IF model scored {valid_count}/{n_total} sessions "
          f"({valid_count/n_total*100:.0f}% had non-zero timing features)")
    print()

    # ── Summary ───────────────────────────────────────────────────────────────
    print(SEP)
    print("  Summary")
    print(SEP)
    print()
    print(f"  {'Signal':<42} {'Acc':>6}  {'F1':>6}  {'AUC':>6}  {'FP%':>5}  {'Recall%':>7}")
    print(f"  {'-'*42} {'-'*6}  {'-'*6}  {'-'*6}  {'-'*5}  {'-'*7}")
    for label, m, show_auc in [
        ("IF only (timing, 4 features)",  m_if,          True),
        ("RF only (HTTP behavior, 10 f)", m_rf,          True),
        ("Heuristic only",                m_h,           True),
        ("Fused (SUSPICIOUS+BEACON)",     m_fused_any,   True),
        ("Fused (BEACON only)",           m_fused_strict,True),
    ]:
        auc_str = f"{m['auc']:.3f}" if m['auc'] == m['auc'] else "n/a"
        print(f"  {label:<42} {m['acc']*100:>5.1f}%  {m['mf1']:>6.4f}  {auc_str:>6}  "
              f"{m['fp_rate']:>4.1f}%  {m['recall']:>6.1f}%")
    print()
    print("  Interpretation:")
    print("  - RF classifier dominates because it was trained on the same data distribution.")
    print("  - IF model reflects a domain shift: trained on pcap (ms precision),")
    print("    scored on server logs (s precision) — this is expected degradation.")
    print("  - Heuristic contributes little without browser-context features.")
    print("    In live CDP sessions, heuristic rules activate fully.")
    print("  - Fusion at SUSPICIOUS threshold adds recall; BEACON threshold reduces FP.")
    print()
    print(SEP)
    print()


if __name__ == "__main__":
    main()
