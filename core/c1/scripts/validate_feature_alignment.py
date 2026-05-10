"""Validate feature alignment between extractor and trained feature list."""
from __future__ import annotations

import json
import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.c1.features import extract_manifest_features, build_feature_vector


def main() -> None:
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    feature_path = os.path.join(base_dir, "data", "dataset_clean_v3_features.json")

    with open(feature_path, "r", encoding="utf-8") as handle:
        feature_columns = json.load(handle)

    sample_manifest = {
        "permissions": ["tabs", "storage", "webRequest", "cookies"],
        "host_permissions": ["<all_urls>"],
        "background": {"service_worker": "background.js"},
        "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"]}],
    }
    sample_source = "document.addEventListener('keydown', () => {});"

    features = extract_manifest_features(sample_manifest, sample_source)
    vector = build_feature_vector(feature_columns, features)

    missing = [name for name in feature_columns if name not in features]

    print(f"Feature list count: {len(feature_columns)}")
    print(f"Vector length: {len(vector)}")
    print(f"Extractor features: {len(features)}")
    print(f"Missing from extractor: {missing}")


if __name__ == "__main__":
    main()
