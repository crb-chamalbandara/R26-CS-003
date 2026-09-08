"""
Generate the two publication figures for the C3 ICAC2026 paper from real
project data (data/_c3_scoped_model_results.json,
data/_c3_classifier_comparison_scoped_results.json). No numbers are typed by
hand into this script beyond axis/label cosmetics.

Outputs (300 DPI, paper/figures/):
  fig1_architecture.png   pipeline diagram (drawn, not data-driven)
  fig2_headline_results.png   LOFO vs LOPO, 5 metrics, from real JSON
  fig3_classifier_comparison.png   why XGBoost, from real JSON
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle, Circle, Polygon, Arc
import numpy as np

# IEEE places the figure caption below the figure, produced by the LaTeX
# \caption{} command. Rendering a title inside the PNG as well would
# duplicate it, so in-image titles are disabled for the submission build.
SHOW_TITLES = False

REPO = Path(__file__).resolve().parent.parent
FIGDIR = Path(__file__).resolve().parent / "figures"
FIGDIR.mkdir(exist_ok=True)

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 9,
    "axes.edgecolor": "#333333",
    "axes.linewidth": 0.8,
    "savefig.dpi": 300,
})

# ─────────────────────────────────────────────────────────────────────────
# Figure 1: pipeline / architecture diagram — hand-drawn line icons,
# strictly black-on-white (a light grey is used only for the swimlane
# backgrounds, which is a neutral shade, not a colour).
# ─────────────────────────────────────────────────────────────────────────
def _icon_browser(ax, cx, cy, s):
    w, h = 1.9 * s, 1.5 * s
    x0, y0 = cx - w / 2, cy - h / 2
    ax.add_patch(Rectangle((x0, y0), w, h, fill=False, ec="black", lw=1.1, zorder=5))
    bar = h * 0.30
    ax.plot([x0, x0 + w], [y0 + h - bar, y0 + h - bar], color="black", lw=1.0, zorder=5)
    for i in range(3):
        dot_x = x0 + w * (0.16 + i * 0.13)
        ax.add_patch(Circle((dot_x, y0 + h - bar / 2), bar * 0.17,
                             fc="black", ec="none", zorder=5))


def _icon_broadcast(ax, cx, cy, s):
    ox, oy = cx - 0.35 * s, cy - 0.45 * s
    ax.add_patch(Circle((ox, oy), 0.15 * s, fc="black", ec="none", zorder=5))
    for r in (0.62 * s, 1.05 * s):
        ax.add_patch(Arc((ox, oy), 2 * r, 2 * r, angle=0, theta1=28, theta2=82,
                          ec="black", lw=1.1, zorder=5))
    ax.add_patch(Rectangle((cx + 0.05 * s, cy + 0.25 * s), 0.55 * s, 0.42 * s,
                            fill=False, ec="black", lw=1.0, zorder=5))


def _icon_cursor(ax, cx, cy, s):
    pts = [(cx - 0.55 * s, cy + 0.75 * s), (cx - 0.55 * s, cy - 0.55 * s),
           (cx - 0.20 * s, cy - 0.20 * s), (cx + 0.02 * s, cy - 0.68 * s),
           (cx + 0.27 * s, cy - 0.56 * s), (cx + 0.04 * s, cy - 0.10 * s),
           (cx + 0.50 * s, cy - 0.02 * s)]
    ax.add_patch(Polygon(pts, closed=True, fc="black", ec="black", lw=0.8, zorder=5))
    ax.add_patch(Circle((cx + 0.58 * s, cy + 0.62 * s), 0.15 * s,
                         fill=False, ec="black", lw=1.1, zorder=5))


def _icon_stack(ax, cx, cy, s):
    w, h, gap = 1.7 * s, 0.40 * s, 0.16 * s
    for i in range(3):
        y0 = cy - 1.5 * h - gap + i * (h + gap)
        ax.add_patch(Rectangle((cx - w / 2, y0), w, h, fill=False, ec="black", lw=1.1, zorder=5))


def _icon_gear(ax, cx, cy, s):
    outer_r, inner_r, hole_r = 0.88 * s, 0.56 * s, 0.26 * s
    teeth = 8
    for i in range(teeth):
        ang = 2 * np.pi * i / teeth
        x1, y1 = cx + inner_r * np.cos(ang), cy + inner_r * np.sin(ang)
        x2, y2 = cx + outer_r * np.cos(ang), cy + outer_r * np.sin(ang)
        ax.plot([x1, x2], [y1, y2], color="black", lw=2.4, solid_capstyle="butt", zorder=5)
    ax.add_patch(Circle((cx, cy), inner_r, fill=False, ec="black", lw=1.2, zorder=5))
    ax.add_patch(Circle((cx, cy), hole_r, fc="white", ec="black", lw=1.0, zorder=6))


def _icon_tree(ax, cx, cy, s):
    root = (cx, cy + 0.68 * s)
    c1, c2 = (cx - 0.55 * s, cy + 0.02 * s), (cx + 0.55 * s, cy + 0.02 * s)
    l1, l2 = (cx - 0.85 * s, cy - 0.70 * s), (cx - 0.22 * s, cy - 0.70 * s)
    l3, l4 = (cx + 0.22 * s, cy - 0.70 * s), (cx + 0.85 * s, cy - 0.70 * s)
    for a, b in [(root, c1), (root, c2), (c1, l1), (c1, l2), (c2, l3), (c2, l4)]:
        ax.plot([a[0], b[0]], [a[1], b[1]], color="black", lw=1.0, zorder=4)
    for pt, r in [(root, 0.14 * s), (c1, 0.11 * s), (c2, 0.11 * s),
                  (l1, 0.095 * s), (l2, 0.095 * s), (l3, 0.095 * s), (l4, 0.095 * s)]:
        ax.add_patch(Circle(pt, r, fc="white", ec="black", lw=1.1, zorder=5))


def _icon_checklist(ax, cx, cy, s):
    w, h = 1.5 * s, 1.9 * s
    x0, y0 = cx - w / 2, cy - h / 2
    ax.add_patch(Rectangle((x0, y0), w, h, fill=False, ec="black", lw=1.1, zorder=5))
    ax.add_patch(Rectangle((cx - 0.24 * s, y0 + h - 0.10 * s), 0.48 * s, 0.20 * s,
                            fc="white", ec="black", lw=1.0, zorder=6))
    for i in range(3):
        yy = y0 + h * 0.70 - i * h * 0.30
        ax.plot([x0 + 0.14 * w, x0 + 0.27 * w, x0 + 0.46 * w],
                 [yy, yy - 0.09 * s, yy + 0.15 * s], color="black", lw=1.1, zorder=6)
        ax.plot([x0 + 0.56 * w, x0 + 0.87 * w], [yy, yy], color="black", lw=0.9, zorder=6)


def _icon_shield(ax, cx, cy, s):
    w, h = 1.35 * s, 1.85 * s
    top = cy + h / 2
    pts = [(cx - w / 2, top - 0.12 * h), (cx - w / 2, top - 0.62 * h), (cx, cy - h / 2),
           (cx + w / 2, top - 0.62 * h), (cx + w / 2, top - 0.12 * h), (cx, top)]
    ax.add_patch(Polygon(pts, closed=True, fill=False, ec="black", lw=1.2, zorder=5))
    ax.plot([cx - 0.26 * s, cx - 0.04 * s, cx + 0.30 * s],
             [cy, cy - 0.20 * s, cy + 0.26 * s], color="black", lw=1.2, zorder=6)


def _icon_merge(ax, cx, cy, s):
    end = (cx + 0.35 * s, cy)
    for p in [(cx - 0.85 * s, cy + 0.62 * s), (cx - 0.9 * s, cy), (cx - 0.85 * s, cy - 0.62 * s)]:
        ax.plot([p[0], end[0]], [p[1], end[1]], color="black", lw=1.0, zorder=4)
    ax.add_patch(Circle(end, 0.08 * s, fc="black", ec="none", zorder=6))
    ax.annotate("", xy=(end[0] + 0.55 * s, cy), xytext=end,
                arrowprops=dict(arrowstyle="-|>", color="black", lw=1.3, mutation_scale=9),
                zorder=6)


def fig1_architecture():
    fig, ax = plt.subplots(figsize=(8.4, 7.6))
    ax.set_xlim(-24, 104); ax.set_ylim(-3, 122)
    ax.set_aspect("equal", adjustable="box")  # icons render as true circles, not ellipses
    ax.axis("off")

    def box(x, y, w, h, text, icon=None, fs=7.7, lw=1.2):
        p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.5,rounding_size=1.6",
                            linewidth=lw, edgecolor="black", facecolor="white", zorder=3)
        ax.add_patch(p)
        if icon is not None:
            # Icon pictogram on top, thin rule, wrapped label below — full box
            # width stays free for text, so long labels never collide with the icon.
            icon_s = min(w * 0.15, h * 0.19)
            icon(ax, x + w / 2, y + h * 0.745, icon_s)
            div_y = y + h * 0.535
            ax.plot([x + w * 0.09, x + w * 0.91], [div_y, div_y],
                     color="black", lw=0.7, zorder=4)
            ax.text(x + w / 2, y + h * 0.27, text, ha="center", va="center",
                     fontsize=fs, color="black", zorder=5, linespacing=1.3)
        else:
            ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
                     color="black", zorder=5, linespacing=1.32)
        return (x, y, w, h)

    def arrow(b1, b2, style="-|>", side1="right", side2="left", color="black",
              lw=1.15, ls="solid"):
        x1, y1, w1, h1 = b1; x2, y2, w2, h2 = b2
        p1 = {"right": (x1+w1, y1+h1/2), "left": (x1, y1+h1/2),
              "top": (x1+w1/2, y1+h1), "bottom": (x1+w1/2, y1)}[side1]
        p2 = {"right": (x2+w2, y2+h2/2), "left": (x2, y2+h2/2),
              "top": (x2+w2/2, y2+h2), "bottom": (x2+w2/2, y2)}[side2]
        a = FancyArrowPatch(p1, p2, arrowstyle=style, mutation_scale=10,
                             linewidth=lw, linestyle=ls, color=color, zorder=2,
                             shrinkA=0, shrinkB=0)
        ax.add_patch(a)

    def lane(y0, h, num, label):
        ax.add_patch(FancyBboxPatch((-22, y0), 127, h, boxstyle="square,pad=0",
                                     linewidth=0, facecolor="#f2f2f2", zorder=0))
        ax.text(-12.5, y0 + h / 2, f"{num}  {label}", fontsize=8.6, weight="bold",
                 color="black", ha="center", va="center", rotation=90,
                 rotation_mode="anchor", zorder=1)

    # Four contiguous swimlanes, framed, top (collection) to bottom (verdict).
    # Stage names live in a rotated sidebar column so they never compete with
    # the row above for vertical space.
    BOUND = [0, 27, 58, 86, 114]
    lane(BOUND[3], BOUND[4]-BOUND[3], "1", "COLLECTION")
    lane(BOUND[2], BOUND[3]-BOUND[2], "2", "FEATURES")
    lane(BOUND[1], BOUND[2]-BOUND[1], "3", "SIGNALS")
    lane(BOUND[0], BOUND[1]-BOUND[0], "4", "FUSION")
    for yb in BOUND:
        if yb == 27:
            # Leave a gap in this one rule so it doesn't strike through the
            # reputation caption sitting right on the lane boundary.
            ax.plot([-22, 56], [yb, yb], color="black", lw=1.0, zorder=1)
            ax.plot([76, 103], [yb, yb], color="black", lw=1.0, zorder=1)
        else:
            ax.plot([-22, 103], [yb, yb], color="black", lw=1.0, zorder=1)
    ax.plot([-3, -3], [BOUND[0], BOUND[-1]], color="black", lw=0.8, zorder=1)
    for xb in (-22, 103):
        ax.plot([xb, xb], [BOUND[0], BOUND[-1]], color="black", lw=1.0, zorder=1)

    if SHOW_TITLES:
        ax.text(-22, 120, "Fig. 1.  C3 detection pipeline. Analysis runs every 10 s per monitored host.",
                fontsize=8.6, ha="left", va="top", weight="bold", color="black")

    # Lane 1: collection, left to right
    b_browser = box(0, 90, 22, 20, "Managed Chromium\nsession\n(Playwright)", icon=_icon_browser)
    b_cdp = box(26, 90, 24, 20, "CDP Network domain\n(fire-and-forget\nevents, no request\npausing)", icon=_icon_broadcast, fs=7.3)
    b_ctx = box(53, 90, 24, 20, "Init-script context\ntagger — click, key,\nscroll, touch, tab\nvisibility, initiator", icon=_icon_cursor, fs=7.3)
    b_window = box(80, 90, 21, 20, "Per-host window\ndeque(maxlen=50)", icon=_icon_stack)
    arrow(b_browser, b_cdp); arrow(b_cdp, b_ctx); arrow(b_ctx, b_window)

    # Lane 2: feature engine, centered, fed from the window's bottom
    b_feat = box(31, 64, 38, 19, "Feature engine\n29 features / host window\n(18 scale-free ML + 11 context)",
                 icon=_icon_gear, lw=1.6)
    a = FancyArrowPatch((90.5, 90), (50, 83), connectionstyle="arc3,rad=0.15",
                         arrowstyle="-|>", mutation_scale=10, linewidth=1.15,
                         color="black", zorder=2, shrinkA=2, shrinkB=2)
    ax.add_patch(a)

    # Lane 3: three signal boxes, directly below the feature engine
    b_ml = box(1, 33, 27, 20, "ML signal\nisotonic-calibrated\nXGBoost (18 features)", icon=_icon_tree)
    b_heur = box(31, 33, 27, 20, "Heuristic signal\n9 deterministic rules", icon=_icon_checklist)
    b_rep = box(61, 33, 26, 20, "Reputation\nAbuseIPDB + VirusTotal", icon=_icon_shield, fs=7.4)
    arrow(b_feat, b_ml, side1="bottom", side2="top")
    arrow(b_feat, b_heur, side1="bottom", side2="top")

    # Lane 4: fusion, wide, directly below the three signals
    b_fuse = box(6, 4, 76, 19,
                 "Fusion:   score = 0.55 · ML + 0.45 · heuristic\n"
                 "both-signal corroboration guard  ·  ≥10 requests to confirm\n"
                 "verdict:  SAFE  /  SUSPICIOUS  /  BEACON",
                 icon=_icon_merge, fs=7.8, lw=1.6)
    arrow(b_ml, b_fuse, side1="bottom", side2="top")
    arrow(b_heur, b_fuse, side1="bottom", side2="top")
    # Reputation is evidence, not a fusion input: dashed (line style carries
    # the distinction, not colour) and drawn arriving at the verdict text
    # rather than at the fusion sum itself.
    a = FancyArrowPatch((84, 33), (84, 23), connectionstyle="arc3,rad=0.1",
                         arrowstyle="-|>", mutation_scale=10, linewidth=1.1,
                         linestyle=(0, (3, 2)), color="black", zorder=2,
                         shrinkA=2, shrinkB=2)
    ax.add_patch(a)
    ax.text(58, 28, "queried only once\nBEACON is confirmed\n— evidence, not a\nscoring input",
            ha="left", va="center", fontsize=6.6, color="black", style="italic")

    fig.savefig(FIGDIR / "fig1_architecture.png", bbox_inches="tight")
    plt.close(fig)
    print("wrote fig1_architecture.png")


# ─────────────────────────────────────────────────────────────────────────
# Figure 2: headline results, real data
# ─────────────────────────────────────────────────────────────────────────
def fig2_headline():
    """LOPO vs LOFO on the deployed model, black-and-white, driven by
    _paper_numbers.json so the figure cannot drift from the text: both means
    apply the paper's stated reliability rule (a fold needs >= 10 positive
    test windows to enter a mean)."""
    nums = json.loads((Path(__file__).resolve().parent / "_paper_numbers.json").read_text())
    METRICS = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    LABELS = ["Accuracy", "Precision", "Recall", "F1 Score", "ROC-AUC"]
    lopo = [nums["LOPO"]["mean_reliable"][m] for m in METRICS]
    lofo = [nums["LOFO"]["mean_reliable"][m] for m in METRICS]
    n_lopo = nums["LOPO"]["n_folds_reliable"]
    n_lofo = nums["LOFO"]["n_folds_reliable"]

    fig, ax = plt.subplots(figsize=(7.1, 3.2))
    x = np.arange(len(LABELS)); w = 0.36
    b1 = ax.bar(x - w / 2, lopo, w,
                label=f"LOPO - unseen C2 infrastructure ({n_lopo} folds)",
                facecolor="black", edgecolor="black", linewidth=1.0, zorder=3)
    b2 = ax.bar(x + w / 2, lofo, w,
                label=f"LOFO - unseen malware family ({n_lofo} folds)",
                facecolor="white", edgecolor="black", linewidth=1.0,
                hatch="////", zorder=3)
    ax.axhline(0.75, ls="--", lw=1.0, color="black", zorder=2)
    ax.set_xlim(-1.20, len(LABELS) - 0.45)
    ax.text(-1.14, 0.757, "0.75 target", color="black",
            fontsize=7.0, ha="left", va="bottom", style="italic")
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.02,
                     f"{b.get_height():.3f}", ha="center", va="bottom",
                     fontsize=6.6, color="black", zorder=4)
    ax.set_xticks(x); ax.set_xticklabels(LABELS, fontsize=8.4, color="black")
    ax.set_ylim(0, 1.16)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_ylabel("Score", fontsize=8.6, color="black")
    ax.legend(fontsize=7.2, loc="lower center", ncol=1, framealpha=1,
              edgecolor="black")
    ax.grid(axis="y", color="black", alpha=0.12, lw=0.6, zorder=0)
    ax.tick_params(colors="black")
    for s in ax.spines.values():
        s.set_color("black")
    ax.spines[["top", "right"]].set_visible(False)
    if SHOW_TITLES:
        ax.set_title("Fig. 2.  Class-balanced held-out performance, deployed model",
                      fontsize=8.3, loc="left", color="black")
    fig.tight_layout()
    fig.savefig(FIGDIR / "fig2_headline_results.png", bbox_inches="tight")
    plt.close(fig)
    print("wrote fig2_headline_results.png")



# ─────────────────────────────────────────────────────────────────────────
# Figure 3: classifier comparison, real data
# ─────────────────────────────────────────────────────────────────────────
def fig3_classifiers():
    cmp = json.loads((REPO / "data" / "_c3_classifier_comparison_scoped_results.json").read_text())
    names = list(cmp["grouped_random_split"].keys())
    short = {"Logistic Regression": "LogReg", "Naive Bayes": "NaiveBayes",
             "Decision Tree": "DecTree", "Random Forest": "RandForest",
             "XGBoost": "XGBoost"}
    split_auc = [cmp["grouped_random_split"][n]["roc_auc"] for n in names]
    lofo_auc = [cmp["lofo_mean"].get(n, {}).get("roc_auc", 0.0) for n in names]
    lofo_f1 = [cmp["lofo_mean"].get(n, {}).get("f1", 0.0) for n in names]
    labels = [short[n] for n in names]
    x = np.arange(len(names))

    fig, axes = plt.subplots(1, 2, figsize=(7.4, 3.35))

    # ---- (a) ROC-AUC: grouped (optimistic) split vs. LOFO, per classifier --
    ax = axes[0]
    w = 0.36
    b1 = ax.bar(x - w/2, split_auc, w, label="Grouped split (optimistic)",
                facecolor="black", edgecolor="black", linewidth=1.0, zorder=3)
    b2 = ax.bar(x + w/2, lofo_auc, w, label="LOFO (unseen family)",
                facecolor="white", edgecolor="black", linewidth=1.0,
                hatch="////", zorder=3)
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.025,
                     f"{b.get_height():.2f}", ha="center", va="bottom",
                     fontsize=6.5, color="black", zorder=4)
    ax.set_xticks(x); ax.set_xticklabels(labels, rotation=28, ha="right",
                                          fontsize=7.6, color="black")
    ax.set_ylim(0, 1.18)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_ylabel("ROC-AUC", fontsize=8.6, color="black")
    ax.set_title("(a)  Ranking quality (ROC-AUC) survives", fontsize=8.4,
                 loc="left", color="black")
    ax.legend(fontsize=6.8, loc="upper center", ncol=1, framealpha=1,
              edgecolor="black", bbox_to_anchor=(0.30, 1.0))
    ax.grid(axis="y", color="black", alpha=0.12, lw=0.6, zorder=0)
    ax.tick_params(colors="black")
    for s in ax.spines.values():
        s.set_color("black")
    ax.spines[["top", "right"]].set_visible(False)

    # ---- (b) LOFO F1 at the deployed 0.5 threshold: calibration collapses --
    ax = axes[1]
    rf_idx = names.index("Random Forest")
    bars = ax.bar(x, lofo_f1, width=0.55, facecolor="black", edgecolor="black",
                   linewidth=1.0, zorder=3)
    bars[rf_idx].set_facecolor("white")
    bars[rf_idx].set_hatch("xxxx")
    bars[rf_idx].set_linewidth(1.6)
    for b, v in zip(bars, lofo_f1):
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.012,
                 f"{v:.3f}", ha="center", va="bottom", fontsize=6.8,
                 color="black", zorder=4)
    ax.set_xticks(x); ax.set_xticklabels(labels, rotation=28, ha="right",
                                          fontsize=7.6, color="black")
    ax.set_ylim(0, 0.34)
    ax.set_ylabel("LOFO F1  (fixed 0.5 threshold)", fontsize=8.6, color="black")
    ax.set_title("(b)  Threshold calibration does not", fontsize=8.4,
                 loc="left", color="black")
    ax.annotate("Random Forest: 0.000 —\n0% recall on every\nunseen family",
                xy=(rf_idx, 0.006), xytext=(rf_idx - 2.05, 0.175),
                fontsize=6.9, color="black", ha="left",
                arrowprops=dict(arrowstyle="->", color="black", lw=1.0))
    ax.grid(axis="y", color="black", alpha=0.12, lw=0.6, zorder=0)
    ax.tick_params(colors="black")
    for s in ax.spines.values():
        s.set_color("black")
    ax.spines[["top", "right"]].set_visible(False)

    if SHOW_TITLES:
        fig.tight_layout(rect=[0, 0, 1, 0.85])
        fig.suptitle("Fig. 3.  Five classifiers, identical scoped dataset and weighting: Random Forest\n"
                      "wins the optimistic split, then fails to generalize.",
                      fontsize=8.8, weight="bold", y=0.98, color="black")
    else:
        fig.tight_layout()
    fig.savefig(FIGDIR / "fig3_classifier_comparison.png", bbox_inches="tight")
    plt.close(fig)
    print("wrote fig3_classifier_comparison.png")


if __name__ == "__main__":
    fig1_architecture()
    fig2_headline()
    fig3_classifiers()
