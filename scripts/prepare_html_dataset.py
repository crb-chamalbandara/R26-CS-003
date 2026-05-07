"""
scripts/prepare_html_dataset.py
────────────────────────────────
Extracts DOM features from the Mendeley phishing dataset HTML snapshots,
trains an XGBoost/RandomForest classifier, and saves models/bitb_classifier.pkl.

Usage (from project root):
    python scripts/prepare_html_dataset.py

Dataset layout expected at:
    <project_root>/Dataset/n96ncsr5g4-1.zip   OR
    <project_root>/../Dataset/n96ncsr5g4-1.zip  (one level up — no copy needed)
"""
import re
import sys
import os
import zipfile
import pickle
import io
from pathlib import Path
from urllib.parse import urlparse

# ── Paths ──────────────────────────────────────────────────────
REPO_ROOT  = Path(__file__).resolve().parent.parent
OUTER_ZIP  = REPO_ROOT / "Dataset" / "n96ncsr5g4-1.zip"
if not OUTER_ZIP.exists():
    OUTER_ZIP = REPO_ROOT.parent / "Dataset" / "n96ncsr5g4-1.zip"
MODEL_OUT  = REPO_ROOT / "models" / "bitb_classifier.pkl"
CSV_OUT    = REPO_ROOT / "data"   / "html_features.csv"

SAMPLE_PER_CLASS = 15_000   # 30k total — balanced, fast to train

# ── Imports ────────────────────────────────────────────────────
try:
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, f1_score
    from bs4 import BeautifulSoup
except ImportError as e:
    sys.exit(f"Missing dependency: {e}\nRun: pip install scikit-learn pandas numpy beautifulsoup4 lxml")

BRANDS = {
    "paypal", "microsoft", "apple", "amazon", "google", "facebook",
    "instagram", "netflix", "dropbox", "linkedin", "twitter",
    "wellsfargo", "chase", "hsbc", "dhl", "fedex", "irs",
}

FEATURE_COLS = [
    "n_iframes", "has_fixed_iframe", "max_zindex", "full_viewport",
    "drag_prevent", "n_forms", "n_inputs", "n_pw_inputs",
    "n_hidden_inputs", "n_ext_scripts", "form_ext_action",
    "title_brand", "favicon_brand", "has_overlay",
    "has_redirect", "html_size_kb",
]


# ══════════════════════════════════════════════════════════════
#  Step 1 — Parse index.sql
# ══════════════════════════════════════════════════════════════
def parse_index(sql_text: str) -> dict:
    """Return {filename: (url, label)} for all .html records."""
    pattern = re.compile(
        r"\(\s*\d+\s*,\s*'([^']+)'\s*,\s*'([^']*\.html)'\s*,\s*([01])\s*,",
        re.DOTALL,
    )
    index = {}
    for m in pattern.finditer(sql_text):
        url, fn, label = m.group(1), m.group(2), int(m.group(3))
        index[fn] = (url, label)
    return index


# ══════════════════════════════════════════════════════════════
#  Step 2 — Feature extraction
# ══════════════════════════════════════════════════════════════
def extract_html_features(html: str, url: str = "") -> dict:
    """Extract 16 DOM/style features from a raw HTML string."""
    lo = html.lower()
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return {col: 0 for col in FEATURE_COLS}

    iframes = soup.find_all("iframe")
    forms   = soup.find_all("form")
    inputs  = soup.find_all("input")
    scripts = soup.find_all("script")

    # Title and favicon
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.lower()

    favicon_url = ""
    for lnk in soup.find_all("link"):
        rel = lnk.get("rel", [])
        if isinstance(rel, list):
            rel = " ".join(rel)
        if "icon" in rel.lower():
            favicon_url = lnk.get("href", "").lower()
            break

    # Z-index
    zindices = [int(m) for m in re.findall(r"z-index\s*:\s*(\d+)", lo)]
    max_zindex = min(max(zindices) if zindices else 0, 9999)

    # Style features
    has_fixed_iframe = int(
        bool(iframes) and bool(re.search(r"position\s*:\s*fixed", lo))
    )
    full_viewport = int(
        bool(re.search(r"width\s*:\s*100(vw|%)", lo))
        and bool(re.search(r"height\s*:\s*100(vh|%)", lo))
    )
    drag_prevent = int(
        bool(re.search(r"(ondragstart|onselectstart|user-select\s*:\s*none)", lo))
    )

    # Input counts
    n_pw_inputs     = sum(1 for i in inputs if i.get("type", "").lower() == "password")
    n_hidden_inputs = sum(1 for i in inputs if i.get("type", "").lower() == "hidden")

    # External scripts
    n_ext_scripts = sum(
        1 for s in scripts if s.get("src", "").startswith("http")
    )

    # Form action domain mismatch
    form_ext_action = 0
    page_host = urlparse(url).hostname or "" if url else ""
    for f in forms:
        action = f.get("action", "")
        if action.startswith("http") and page_host:
            form_host = urlparse(action).hostname or ""
            if form_host and form_host != page_host:
                form_ext_action = 1
                break

    # Brand checks
    title_brand   = int(any(b in title for b in BRANDS))
    favicon_brand = int(any(b in favicon_url for b in BRANDS))

    # Behavioural
    has_overlay  = int(bool(re.search(r"\b(overlay|modal)\b", lo)))
    has_redirect = int(bool(re.search(r"window\.location", lo)))

    return {
        "n_iframes":        len(iframes),
        "has_fixed_iframe": has_fixed_iframe,
        "max_zindex":       max_zindex,
        "full_viewport":    full_viewport,
        "drag_prevent":     drag_prevent,
        "n_forms":          len(forms),
        "n_inputs":         len(inputs),
        "n_pw_inputs":      n_pw_inputs,
        "n_hidden_inputs":  n_hidden_inputs,
        "n_ext_scripts":    n_ext_scripts,
        "form_ext_action":  form_ext_action,
        "title_brand":      title_brand,
        "favicon_brand":    favicon_brand,
        "has_overlay":      has_overlay,
        "has_redirect":     has_redirect,
        "html_size_kb":     len(html) // 1024,
    }


# ══════════════════════════════════════════════════════════════
#  Step 3 — Stream all 8 part zips and collect samples
# ══════════════════════════════════════════════════════════════
def process_all_parts(outer_zip: zipfile.ZipFile, index: dict) -> pd.DataFrame:
    """Stream through 8 part zips and collect up to SAMPLE_PER_CLASS per label."""
    rows = []
    collected = {0: 0, 1: 0}
    needed    = {0: SAMPLE_PER_CLASS, 1: SAMPLE_PER_CLASS}

    part_names = sorted(
        n for n in outer_zip.namelist()
        if re.search(r"dataset_part_\d+\.zip$", n)
    )
    print(f"Found {len(part_names)} part zips")

    for part_name in part_names:
        if all(collected[k] >= needed[k] for k in (0, 1)):
            break
        print(f"  Processing {part_name.split('/')[-1]} …", end=" ", flush=True)
        try:
            part_bytes = outer_zip.read(part_name)
            part_zip   = zipfile.ZipFile(io.BytesIO(part_bytes))
        except Exception as e:
            print(f"skip ({e})")
            continue

        html_names = [n for n in part_zip.namelist() if n.endswith(".html")]
        part_count = 0
        for entry in html_names:
            fn = entry.split("/")[-1]
            if fn not in index:
                continue
            url, label = index[fn]
            if collected[label] >= needed[label]:
                continue
            try:
                html = part_zip.read(entry).decode("utf-8", errors="replace")
                feats = extract_html_features(html, url)
                feats["label"] = label
                rows.append(feats)
                collected[label] += 1
                part_count += 1
                total = collected[0] + collected[1]
                grand_total = needed[0] + needed[1]
                if total % 500 == 0:
                    pct = total / grand_total * 100
                    print(f"    [{pct:5.1f}%] {total:,}/{grand_total:,} collected "
                          f"(phish={collected[1]:,} legit={collected[0]:,})", flush=True)
            except Exception:
                continue

        print(f"  >> Part done: {part_count} samples "
              f"| Total: phish={collected[1]:,} legit={collected[0]:,}", flush=True)

    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════════
#  Step 4 — Train
# ══════════════════════════════════════════════════════════════
def train(df: pd.DataFrame):
    X = df[FEATURE_COLS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Training on {len(X_train):,} / testing on {len(X_test):,}")
    print(f"Class balance — phishing: {y_train.sum()} / legit: {(y_train==0).sum()}")

    try:
        from xgboost import XGBClassifier
        # Try GPU first (GTX 1050 / CUDA), fall back to CPU if unavailable
        try:
            model = XGBClassifier(
                n_estimators=300, max_depth=6, learning_rate=0.1,
                subsample=0.8, colsample_bytree=0.8,
                eval_metric="logloss", random_state=42,
                device="cuda",
            )
            # Quick probe to confirm CUDA works
            import numpy as _np
            _Xp = _np.zeros((2, len(FEATURE_COLS))); _yp = _np.array([0, 1])
            model.fit(_Xp, _yp)
            model_name = "XGBoost (GPU/CUDA)"
            print("  GPU detected — training on GTX 1050", flush=True)
        except Exception as _gpu_err:
            print(f"  GPU not available ({_gpu_err}) — falling back to CPU", flush=True)
            model = XGBClassifier(
                n_estimators=300, max_depth=6, learning_rate=0.1,
                subsample=0.8, colsample_bytree=0.8,
                eval_metric="logloss", random_state=42,
            )
            model_name = "XGBoost (CPU)"
    except ImportError:
        model = RandomForestClassifier(
            n_estimators=300, max_depth=10, random_state=42, n_jobs=-1
        )
        model_name = "RandomForest"

    print(f"Fitting {model_name} ...", flush=True)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    f1 = f1_score(y_test, y_pred)
    print(f"\n{model_name} F1 on test set: {f1:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))
    return model


# ══════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════
def main():
    if not OUTER_ZIP.exists():
        sys.exit(f"Dataset not found at {OUTER_ZIP}")

    print(f"Opening {OUTER_ZIP} ...")
    outer_zip = zipfile.ZipFile(OUTER_ZIP)

    print("Parsing index.sql ...")
    sql_text = outer_zip.read("n96ncsr5g4-1/index.sql").decode("utf-8", errors="replace")
    index = parse_index(sql_text)
    phish_n = sum(1 for _, lbl in index.values() if lbl == 1)
    print(f"  {len(index):,} HTML records  (phishing={phish_n:,} / legit={len(index)-phish_n:,})")

    print(f"\nCollecting up to {SAMPLE_PER_CLASS:,} samples per class from HTML files ...")
    df = process_all_parts(outer_zip, index)
    print(f"\nFeature matrix: {df.shape}")

    CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(CSV_OUT, index=False)
    print(f"Saved feature CSV -> {CSV_OUT}")

    model = train(df)

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_OUT, "wb") as f:
        pickle.dump(model, f)
    print(f"\nModel saved -> {MODEL_OUT}")
    print("Restart the FastAPI backend to load the trained BitB classifier.")


if __name__ == "__main__":
    main()
