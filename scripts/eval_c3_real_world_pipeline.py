"""
Real-world END-TO-END evaluation of C3's beacon-detection pipeline.

WHY THIS SCRIPT EXISTS AND HOW IT DIFFERS FROM scripts/train_c3_18feat.py
--------------------------------------------------------------------------
train_c3_18feat.py measures the RAW CLASSIFIER (XGBClassifier.predict_proba)
against offline-computed features. That answers "is the model any good", but
it is not the number that matters operationally: C3 never ships a raw ML
score to an analyst. What ships is a VERDICT (SAFE / SUSPICIOUS / BEACON)
produced by three real, separate pieces of production code run in sequence:

    core.c3.feature_engine.compute_features()      <- the SAME function the
                                                        live interceptor calls
    core.c3.anomaly_engine.C3XGBoostEngine.score()  <- the SAME class the
                                                        live analyzer calls
    core.c3.analyzer.C3Analyzer._heuristic_score()  <- the SAME static method
                                                        the live analyzer calls
    core.c3.risk_fusion.c3_risk_fusion.fuse()       <- the SAME fusion object
                                                        the live analyzer uses

This script imports and calls those four pieces directly — not a
reimplementation, not a mock. It answers "if this exact real captured traffic
arrived at the live pipeline today, what would the analyst actually see."

NO SYNTHETIC DATA. Every window scored here is real HTTP requests from a
public, labelled malware or benign capture (the same corpus as
build_c3_18feat_dataset.py). Nothing about the REQUEST-LEVEL signal is
invented.

THE ONE THING THAT CANNOT BE MEASURED HONESTLY, AND WHY
---------------------------------------------------------
C3's heuristic layer and two of its three signals (idle time, tab
visibility, extension origin) depend on BROWSER CONTEXT — data that no
network capture, however real, contains. A 2011 Zeek http.log has no idea
whether a human was looking at the screen. Fabricating "yes, idle, yes,
background" as if it were measured would violate the project's own
no-synthetic-data rule as surely as inventing a request would.

So this script evaluates TWO clearly separated, honestly labelled
conditions and never blends them into one number:

  CONDITION A - "context-blind"
    Every browser-context field is set to the exact SAME conservative
    fallback core/c3/interceptor.py itself already uses when it cannot
    determine context (see interceptor.py's _try_finalize exception
    handler): idle_time_ms=0, user_was_active=True, is_background_tab=False,
    is_extension_origin=False. This is not a guess invented for this
    script — it is the production system's own documented "assume benign"
    default. Under this condition, context-gated heuristic rules (2, 3, 4,
    5) mathematically cannot fire (they require uar<0.5 or bg>0.8, and both
    are pinned to their most-benign value). This measures a genuine LOWER
    BOUND: what the pipeline does with signal alone, no context help at
    all — the worst case a real deployment would ever see, since a real
    deployment either has real context (better than this) or falls back to
    exactly this default (no worse than this).

  CONDITION B - "assumed background/idle" (an explicit ASSUMPTION, not data)
    idle_time_ms=200000, user_was_active=False, is_background_tab=True,
    initiator_type="script". This is C3's own stated threat model for a
    browser-borne beacon (see the paper's Introduction) applied to real
    network-level C2 traffic as an illustration of the intended full
    3-signal behaviour. It is labelled everywhere it is printed as an
    ASSUMPTION, never reported as a measured accuracy figure on its own.

Run:  python scripts/eval_c3_real_world_pipeline.py
Writes: data/_c3_real_world_pipeline_results.json
Reads-only: nothing in core/, models/, or data/*.csv is modified.
"""
from __future__ import annotations

import importlib.util
import json
import pickle
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, balanced_accuracy_score,
                             confusion_matrix, roc_auc_score)
from xgboost import XGBClassifier

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.c3.feature_engine import compute_features               # noqa: E402
from core.c3.anomaly_engine import C3XGBoostEngine, ML_FEATURE_SUBSET  # noqa: E402
from core.c3.analyzer import C3Analyzer                            # noqa: E402
from core.c3.risk_fusion import c3_risk_fusion, BEACON_THRESHOLD, SUSPICIOUS_THRESHOLD  # noqa: E402
from scripts.train_c3_18feat import NORMAL_FOLD_ASSIGNMENT, family_weights, FEATURES_18  # noqa: E402

DATASET = REPO_ROOT / "data" / "c3_18feat_dataset.csv"
DEPLOYED_MODEL_PATH = REPO_ROOT / "models" / "c3_xgb_classifier_18feat_20260902.pkl"
OUT_RESULTS = REPO_ROOT / "data" / "_c3_real_world_pipeline_results.json"

BUILDER_PATH = REPO_ROOT / "scripts" / "build_c3_18feat_dataset.py"
CTU13_HTTP_ROOT = Path(r"D:\CTU-13-HTTP")
CTU13_BINETFLOW_ROOT = Path(r"D:\CTU-13-Dataset")
MALWARE_ROOT = Path(r"D:\CTU-Malware-Captures-HTTP")
NORMAL_ROOT = Path(r"D:\CTU-Normal-HTTP")

XGB_PARAMS = dict(n_estimators=300, max_depth=4, learning_rate=0.06,
                  min_child_weight=8, subsample=0.85, colsample_bytree=0.85,
                  reg_lambda=2.0, n_jobs=8, random_state=42,
                  eval_metric="aucpr", verbosity=0)
MONOTONE_18 = (-1, 0, -1, -1, 0, -1, +1, -1,
                0, -1, +1, 0,
               -1, -1, 0, 0, 0, +1)

CONTEXT_A = dict(idle_time_ms=0, user_was_active=True,
                 is_background_tab=False, is_extension_origin=False,
                 initiator_type="other")
CONTEXT_B = dict(idle_time_ms=200_000, user_was_active=False,
                 is_background_tab=True, is_extension_origin=False,
                 initiator_type="script")


def _load_builder():
    spec = importlib.util.spec_from_file_location("c3_builder", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


B = _load_builder()


# --------------------------------------------------------------- windows ----
def _events_from_rows(df: pd.DataFrame, context: dict) -> list[dict]:
    """Turn real capture rows into the event-dict shape core/c3/interceptor.py
    produces, under one disclosed context condition."""
    events = []
    for _, row in df.iterrows():
        referer = str(row.get("referrer", "") or "").strip()
        headers = {} if referer in B._MISSING else {"Referer": referer}
        events.append({
            "timestamp": float(row["ts"]),
            "size_bytes": float(row["resp_bytes"]),
            "request_size": float(row["req_bytes"]),
            "url": "https://capture.invalid" + (row["uri"] or "/"),
            "host": "capture.invalid",
            "method": str(row["method"] or "GET").upper(),
            "request_headers": headers,
            **context,
        })
    return events


def _collect_family_windows(family_filter=None) -> dict[str, list[pd.DataFrame]]:
    """Re-parse the raw captures and re-cut them into the SAME non-overlapping
    windows build_c3_18feat_dataset.py uses, but keep the raw per-request rows
    (not pre-computed features) so this script can run them through the LIVE
    feature_engine itself."""
    out: dict[str, list[pd.DataFrame]] = {}

    def add_windows(df, is_c2, group, family):
        if family_filter and family not in family_filter:
            return
        order = np.argsort(df["ts"].to_numpy(float), kind="stable")
        df = df.iloc[order].reset_index(drop=True)
        is_c2 = np.asarray(is_c2)[order]
        pair_all = (df["src"].astype(str) + "->" + df["dst"].astype(str)).to_numpy()
        for pair in pd.unique(pair_all):
            idx = np.flatnonzero(pair_all == pair)
            for start in range(0, len(idx), B.WINDOW_SIZE):
                block = idx[start:start + B.WINDOW_SIZE]
                if len(block) < B.MIN_FLOWS:
                    continue
                ratio = float(np.mean(is_c2[block]))
                if 0.0 < ratio <= 0.5:
                    continue
                label = 1 if ratio > 0.5 else 0
                key = family if label == 1 else "benign"
                out.setdefault(key, []).append(df.iloc[block].assign(_group=group))

    for scenario in B.CTU13_SCENARIOS:
        path = CTU13_HTTP_ROOT / f"scenario_{scenario}_http.log"
        if not path.exists():
            continue
        c2 = B.load_ctu13_c2_tuples(scenario)
        df = B.read_zeek_http(path)
        keys = list(zip(df["src"], df["sport"], df["dst"], df["dport"]))
        is_c2 = np.array([k in c2 for k in keys])
        add_windows(df, is_c2, f"ctu13-s{scenario}", B.CTU13_FAMILY[scenario])

    for folder, group, family in [
        ("CTU-Malware-Capture-Botnet-25-1", "zeus-25-1", "ZeusV1"),
        ("CTU-Malware-Capture-Botnet-26", "zeus-26", "ZeusB26"),
    ]:
        matches = list((MALWARE_ROOT / folder).glob("*.labeled"))
        if not matches:
            continue
        df = B.read_weblog(matches[0])
        is_c2 = df["label"].str.contains(r"-CC\d", regex=True, na=False).to_numpy()
        df = df.drop(columns=["label"])
        add_windows(df, is_c2, group, family)

    for folder, group in [("CTU-Malware-Capture-Botnet-78-1", "zeus-78-1"),
                          ("CTU-Malware-Capture-Botnet-78-2", "zeus-78-2")]:
        path = MALWARE_ROOT / folder / "http.log"
        if not path.exists():
            continue
        df = B.read_zeek_http(path)
        is_c2 = np.array([(s, d) in B.ZEUS78_C2 for s, d in zip(df["src"], df["dst"])])
        add_windows(df, is_c2, group, "Zeus78")

    if family_filter is None or "benign" in (family_filter or {"benign"}):
        for number in B.NORMAL_CAPTURES:
            path = NORMAL_ROOT / f"CTU-Normal-{number}" / "http.log"
            if not path.exists():
                continue
            df = B.read_zeek_http(path)
            add_windows(df, np.zeros(len(df), dtype=bool), f"normal-{number}", "benign")

    return out


# ------------------------------------------------------------ ML engines ----
def _engine_for(model_path: Path) -> C3XGBoostEngine:
    engine = C3XGBoostEngine()
    engine._model_path = model_path
    engine.reload()
    return engine


def _train_lofo_model(df_offline: pd.DataFrame, held_family: str, tmp_dir: Path) -> Path:
    """Retrain a model with `held_family` (and its captures) fully excluded,
    exactly like train_c3_18feat.py's E1 -- but save it as a real pickle so it
    can be loaded through the real C3XGBoostEngine loader, not called as a
    bare sklearn object."""
    fam = df_offline["family"].to_numpy(str)
    grp = df_offline["group"].to_numpy(str)
    y = df_offline["label"].to_numpy(int)
    held_groups = set(pd.unique(grp[(fam == held_family) & (y == 1)]))
    held_groups |= set(NORMAL_FOLD_ASSIGNMENT.get(held_family, []))
    train_mask = ~np.isin(grp, list(held_groups))

    X = df_offline.loc[train_mask, FEATURES_18].to_numpy(float)
    yt = y[train_mask]
    clf = XGBClassifier(monotone_constraints=MONOTONE_18, **XGB_PARAMS)
    clf.fit(X, yt, sample_weight=family_weights(fam[train_mask], yt, grp[train_mask]))

    path = tmp_dir / f"lofo_{held_family}.pkl"
    with open(path, "wb") as fh:
        pickle.dump({"model": clf, "feature_names": FEATURES_18, "threshold": 0.5,
                    "trained_on": f"LOFO excluding {held_family}"}, fh)
    return path


# -------------------------------------------------------------- scoring -----
def score_windows(windows: list[pd.DataFrame], engine: C3XGBoostEngine,
                  context: dict) -> list[dict]:
    out = []
    for w in windows:
        events = _events_from_rows(w, context)
        feats = compute_features(events)
        ml, ml_detail = engine.score(feats)
        heur, flags = C3Analyzer._heuristic_score(feats)
        fused = c3_risk_fusion.fuse(ml, None, heur)
        out.append({
            "ml": ml, "heuristic": round(heur, 4), "fused": fused["score"],
            "verdict": fused["verdict"], "flags": flags, "group": w["_group"].iloc[0],
        })
    return out


def summarize(pos_scores: list[dict], neg_scores: list[dict]) -> dict:
    def verdict_rate(rows, verdict):
        return round(sum(1 for r in rows if r["verdict"] == verdict) / max(len(rows), 1), 4)

    y = np.array([1] * len(pos_scores) + [0] * len(neg_scores))
    fused = np.array([r["fused"] for r in pos_scores + neg_scores])
    ml_only = np.array([r["ml"] if r["ml"] is not None else 0.0 for r in pos_scores + neg_scores])

    out = {
        "n_positive": len(pos_scores), "n_negative": len(neg_scores),
        "positive_verdicts": {
            "BEACON": verdict_rate(pos_scores, "BEACON"),
            "SUSPICIOUS": verdict_rate(pos_scores, "SUSPICIOUS"),
            "SAFE": verdict_rate(pos_scores, "SAFE"),
        },
        "negative_verdicts": {
            "BEACON": verdict_rate(neg_scores, "BEACON"),
            "SUSPICIOUS": verdict_rate(neg_scores, "SUSPICIOUS"),
            "SAFE": verdict_rate(neg_scores, "SAFE"),
        },
        "recall_at_BEACON": verdict_rate(pos_scores, "BEACON"),
        "recall_at_BEACON_or_SUSPICIOUS": round(
            (verdict_rate(pos_scores, "BEACON") + verdict_rate(pos_scores, "SUSPICIOUS")), 4),
        "false_positive_rate_BEACON": verdict_rate(neg_scores, "BEACON"),
        "false_positive_rate_BEACON_or_SUSPICIOUS": round(
            (verdict_rate(neg_scores, "BEACON") + verdict_rate(neg_scores, "SUSPICIOUS")), 4),
    }
    if len(pos_scores) and len(neg_scores):
        out["fused_score_roc_auc"] = round(float(roc_auc_score(y, fused)), 4)
        out["fused_score_pr_auc"] = round(float(average_precision_score(y, fused)), 4)
        pred = (fused >= BEACON_THRESHOLD).astype(int)
        out["end_to_end_balanced_accuracy_at_BEACON_threshold"] = round(
            float(balanced_accuracy_score(y, pred)), 4)
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
        out["confusion_at_BEACON_threshold"] = {"tp": int(tp), "fp": int(fp),
                                                "fn": int(fn), "tn": int(tn)}
    return out


def main() -> None:
    df_offline = pd.read_csv(DATASET)
    print("Re-parsing raw captures into real request windows (this reads D:\\ again)...")
    families = _collect_family_windows()
    for fam, wins in families.items():
        print(f"  {fam:10s} {len(wins):5d} windows")
    benign_windows = families.pop("benign", [])
    print(f"\n{len(benign_windows)} real benign windows available as negatives.\n")

    results = {}

    # ------------------------------------------------------------------
    print("=" * 78)
    print("TEST 1 - DEPLOYED MODEL, full live pipeline, ALL real families")
    print("(mix of in-sample and unseen data -- family sizes disclosed)")
    print("=" * 78)
    deployed = _engine_for(DEPLOYED_MODEL_PATH)
    neg_sample = benign_windows[:2000]  # cap for runtime; still thousands of real windows
    for cond_name, ctx in [("A_context_blind", CONTEXT_A), ("B_assumed_background_idle", CONTEXT_B)]:
        results.setdefault("test1_deployed_model", {})[cond_name] = {}
        neg_scores = score_windows(neg_sample, deployed, ctx)
        for fam, wins in families.items():
            pos_scores = score_windows(wins, deployed, ctx)
            summary = summarize(pos_scores, neg_scores)
            results["test1_deployed_model"][cond_name][fam] = summary
            print(f"  [{cond_name}] {fam:9s} n={summary['n_positive']:5d}  "
                  f"BEACON={summary['positive_verdicts']['BEACON']:.4f}  "
                  f"BEACON+SUSP={summary['recall_at_BEACON_or_SUSPICIOUS']:.4f}  "
                  f"FPR(BEACON)={summary['false_positive_rate_BEACON']:.4f}", flush=True)

    # ------------------------------------------------------------------
    print()
    print("=" * 78)
    print("TEST 2 - LEAVE-ONE-FAMILY-OUT, full live pipeline (true generalisation)")
    print("=" * 78)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        for cond_name, ctx in [("A_context_blind", CONTEXT_A), ("B_assumed_background_idle", CONTEXT_B)]:
            results.setdefault("test2_lofo", {})[cond_name] = {}
            for fam, wins in families.items():
                if len(wins) < 10:
                    print(f"  [{cond_name}] {fam:9s} SKIPPED (<10 real positive windows)")
                    continue
                model_path = _train_lofo_model(df_offline, fam, tmp_dir)
                engine = _engine_for(model_path)
                held_normal_groups = set(w["_group"].iloc[0] for w in benign_windows) & set(
                    NORMAL_FOLD_ASSIGNMENT.get(fam, []))
                held_neg = [w for w in benign_windows if w["_group"].iloc[0] in held_normal_groups] or neg_sample
                pos_scores = score_windows(wins, engine, ctx)
                neg_scores = score_windows(held_neg, engine, ctx)
                summary = summarize(pos_scores, neg_scores)
                results["test2_lofo"][cond_name][fam] = summary
                print(f"  [{cond_name}] {fam:9s} n_pos={summary['n_positive']:5d} "
                      f"n_neg={summary['n_negative']:5d}  "
                      f"BEACON={summary['positive_verdicts']['BEACON']:.4f}  "
                      f"BEACON+SUSP={summary['recall_at_BEACON_or_SUSPICIOUS']:.4f}  "
                      f"FPR(BEACON)={summary['false_positive_rate_BEACON']:.4f}  "
                      f"ROC={summary.get('fused_score_roc_auc')}", flush=True)

    OUT_RESULTS.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_RESULTS, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1, default=str)
    print(f"\nwrote {OUT_RESULTS}")


if __name__ == "__main__":
    main()
