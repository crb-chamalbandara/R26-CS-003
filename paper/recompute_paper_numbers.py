"""
Derives every evaluation number quoted in the paper directly from the saved
result artifacts, applying the paper's stated reliability rule (a fold needs
>= MIN_POS test-positive windows to enter a mean) CONSISTENTLY to both the
LOFO and the LOPO protocol.

Reads : data/_c3_scoped_model_results.json
        data/_c3_classifier_comparison_scoped_results.json
        data/_c3_fusion_weight_sweep.json
Writes: paper/_paper_numbers.json      (single source of truth for the paper)
"""
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MIN_POS = 10                      # the paper's stated reliability threshold
METRICS = ["accuracy", "precision", "recall", "f1", "roc_auc"]

scoped = json.loads((REPO / "data" / "_c3_scoped_model_results.json").read_text())


def mean_over(folds, keep):
    sel = [f for f in folds if keep(f)]
    return ({m: round(sum(f[m] for f in sel) / len(sel), 4) for m in METRICS},
            len(sel))


lofo_folds = [dict(v, name=k) for k, v in scoped["LOFO"].items()]
lopo_folds = [dict(v, name=k) for k, v in scoped["LOPO"].items()]

reliable = lambda f: f["n_test_positives"] >= MIN_POS

lofo_rel, n_lofo_rel = mean_over(lofo_folds, reliable)
lopo_rel, n_lopo_rel = mean_over(lopo_folds, reliable)
lopo_all, n_lopo_all = mean_over(lopo_folds, lambda f: True)

out = {
    "min_pos_reliable": MIN_POS,
    "scope": scoped["scope"],
    "LOFO": {
        "n_folds_total": len(lofo_folds),
        "n_folds_reliable": n_lofo_rel,
        "reliable_names": sorted(f["name"] for f in lofo_folds if reliable(f)),
        "excluded": {f["name"]: f["n_test_positives"]
                     for f in lofo_folds if not reliable(f)},
        "mean_reliable": lofo_rel,
        "per_family": {f["name"]: {m: round(f[m], 4) for m in METRICS}
                       | {"n_test_positives": f["n_test_positives"]}
                       for f in lofo_folds},
    },
    "LOPO": {
        "n_folds_total": n_lopo_all,
        "n_folds_reliable": n_lopo_rel,
        "excluded_fold_sizes": sorted(f["n_test_positives"]
                                      for f in lopo_folds if not reliable(f)),
        "mean_reliable": lopo_rel,
        "mean_all_folds_unfiltered": lopo_all,
        "reliable_fold_sizes": sorted((f["n_test_positives"]
                                       for f in lopo_folds if reliable(f)),
                                      reverse=True),
    },
    "published_as_reported_previously": scoped["LOPO_mean"],
    "out_of_scope": scoped["out_of_scope"],
}

(Path(__file__).resolve().parent / "_paper_numbers.json").write_text(
    json.dumps(out, indent=2))

print(f"LOFO  reliable folds = {n_lofo_rel}/{len(lofo_folds)} "
      f"{out['LOFO']['reliable_names']}")
print(f"      mean {lofo_rel}")
print(f"      excluded {out['LOFO']['excluded']}")
print()
print(f"LOPO  reliable folds = {n_lopo_rel}/{n_lopo_all} "
      f"sizes {out['LOPO']['reliable_fold_sizes']}")
print(f"      mean (rule applied)   {lopo_rel}")
print(f"      mean (all {n_lopo_all}, unfiltered) {lopo_all}")
print(f"      excluded fold sizes   {out['LOPO']['excluded_fold_sizes']}")
