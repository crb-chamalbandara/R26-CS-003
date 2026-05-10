"""
Phase 1 data setup for Component 1 (C1).
Builds malicious/benign ID lists and a unified CSV template.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
from typing import Iterable, List, Dict, Set, Tuple

EXT_ID_RE = re.compile(r"^[a-p]{32}$")


def _normalize_id(raw: str) -> str:
    return raw.strip().lower()


def _is_valid_id(ext_id: str) -> bool:
    return bool(EXT_ID_RE.match(ext_id))


def _read_text_ids(path: str) -> List[str]:
    ids: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            value = _normalize_id(line)
            if value:
                ids.append(value)
    return ids


def _read_csv_ids(path: str) -> List[str]:
    ids: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return ids
        normalized = {
            f.lower().strip().lstrip("\ufeff").strip("\"").strip("'"): f
            for f in reader.fieldnames
        }
        id_keys = {"id", "extension_id", "extensionid", "ext_id"}
        target = next((normalized[k] for k in id_keys if k in normalized), None)
        if not target:
            return ids
        for row in reader:
            raw = row.get(target, "")
            value = _normalize_id(raw)
            if value:
                ids.append(value)
    return ids


def _read_csv_ids_with_labels(path: str) -> Tuple[List[str], List[str], List[str]]:
    malicious: List[str] = []
    benign: List[str] = []
    mixed: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return malicious, benign, mixed
        normalized = {
            f.lower().strip().lstrip("\ufeff").strip("\"").strip("'"): f
            for f in reader.fieldnames
        }
        id_keys = {"id", "extension_id", "extensionid", "ext_id"}
        label_keys = {"label", "class", "target", "verdict"}
        id_target = next((normalized[k] for k in id_keys if k in normalized), None)
        label_target = next((normalized[k] for k in label_keys if k in normalized), None)
        if not id_target or not label_target:
            return malicious, benign, mixed

        for row in reader:
            raw_id = row.get(id_target, "")
            raw_label = str(row.get(label_target, "")).strip().lower()
            value = _normalize_id(raw_id)
            if not value:
                continue
            if raw_label in {"1", "malicious", "mal", "bad"}:
                malicious.append(value)
            elif raw_label in {"0", "benign", "safe", "good"}:
                benign.append(value)
            elif raw_label in {"mixed", "suspicious"}:
                mixed.append(value)
    return malicious, benign, mixed


def _read_json_ids(path: str) -> List[str]:
    ids: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                value = _normalize_id(item)
                if value:
                    ids.append(value)
            elif isinstance(item, dict):
                for key in ("id", "extension_id", "extensionId", "ext_id"):
                    if key in item and item[key]:
                        value = _normalize_id(str(item[key]))
                        if value:
                            ids.append(value)
                        break
    elif isinstance(data, dict):
        for key in ("extensions", "items", "data"):
            if key in data and isinstance(data[key], list):
                ids.extend(_read_json_ids_from_list(data[key]))
        for key in ("id", "extension_id", "extensionId", "ext_id"):
            if key in data:
                value = _normalize_id(str(data[key]))
                if value:
                    ids.append(value)
    return ids


def _read_json_ids_from_list(items: List[object]) -> List[str]:
    ids: List[str] = []
    for item in items:
        if isinstance(item, str):
            value = _normalize_id(item)
            if value:
                ids.append(value)
        elif isinstance(item, dict):
            for key in ("id", "extension_id", "extensionId", "ext_id"):
                if key in item and item[key]:
                    value = _normalize_id(str(item[key]))
                    if value:
                        ids.append(value)
                    break
    return ids


def _read_ids(path: str) -> List[str]:
    _, ext = os.path.splitext(path.lower())
    if ext == ".json":
        return _read_json_ids(path)
    if ext == ".csv":
        return _read_csv_ids(path)
    return _read_text_ids(path)


def _dedupe(ids: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for value in ids:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _filter_valid(ids: Iterable[str]) -> Tuple[List[str], List[str]]:
    valid: List[str] = []
    invalid: List[str] = []
    for value in ids:
        if _is_valid_id(value):
            valid.append(value)
        else:
            invalid.append(value)
    return valid, invalid


def _write_list(path: str, ids: Iterable[str]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for value in ids:
            handle.write(f"{value}\n")


def _write_labels_csv(path: str, rows: Iterable[Dict[str, str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["extension_id", "label", "source"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_feature_template(path: str) -> None:
    columns = [
        "extension_id",
        "has_webRequest",
        "has_all_urls",
        "has_cookies",
        "has_clipboardRead",
        "has_nativeMessaging",
        "has_tabs",
        "has_background_script",
        "host_permission_count",
        "total_permission_count",
        "has_content_scripts",
        "external_domains_count",
        "label",
    ]
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare Phase 1 dataset inputs for C1.")
    parser.add_argument("--chrome-mal-ids", help="Path to chrome-mal-ids list file")
    parser.add_argument("--palant", help="Path to palant list file (json/csv/txt)")
    parser.add_argument("--chrome-stats", help="Path to Chrome-Stats malware export (csv/txt)")
    parser.add_argument("--benign", help="Path to benign extension ID list (csv/txt)")
    parser.add_argument("--labeled-csv", help="CSV with extension_id + label columns")
    parser.add_argument(
        "--out-dir",
        default=os.path.join(os.path.dirname(__file__), "..", "data"),
        help="Output directory for generated files",
    )
    args = parser.parse_args()

    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    malicious_sources: List[Tuple[str, str]] = []
    if args.chrome_mal_ids:
        malicious_sources.append(("chrome-mal-ids", args.chrome_mal_ids))
    if args.palant:
        malicious_sources.append(("palant", args.palant))
    if args.chrome_stats:
        malicious_sources.append(("chrome-stats", args.chrome_stats))

    benign_sources: List[Tuple[str, str]] = []
    if args.benign:
        benign_sources.append(("benign", args.benign))

    malicious_ids: List[str] = []
    for name, path in malicious_sources:
        ids = _read_ids(path)
        malicious_ids.extend(ids)
        print(f"Loaded {len(ids)} IDs from {name}: {path}")

    benign_ids: List[str] = []
    for name, path in benign_sources:
        ids = _read_ids(path)
        benign_ids.extend(ids)
        print(f"Loaded {len(ids)} IDs from {name}: {path}")

    mixed_ids: List[str] = []
    if args.labeled_csv:
        labeled_mal, labeled_ben, labeled_mix = _read_csv_ids_with_labels(args.labeled_csv)
        if labeled_mal or labeled_ben or labeled_mix:
            malicious_ids.extend(labeled_mal)
            benign_ids.extend(labeled_ben)
            mixed_ids.extend(labeled_mix)
            print(
                "Loaded labeled CSV IDs: "
                f"malicious={len(labeled_mal)}, benign={len(labeled_ben)}, mixed={len(labeled_mix)}"
            )
        else:
            print("Warning: labeled CSV did not include extension_id + label columns.")

    malicious_ids = _dedupe(malicious_ids)
    benign_ids = _dedupe(benign_ids)
    mixed_ids = _dedupe(mixed_ids)

    malicious_valid, malicious_invalid = _filter_valid(malicious_ids)
    benign_valid, benign_invalid = _filter_valid(benign_ids)
    mixed_valid, mixed_invalid = _filter_valid(mixed_ids)

    if malicious_invalid:
        print(f"Warning: {len(malicious_invalid)} malicious IDs failed validation.")
    if benign_invalid:
        print(f"Warning: {len(benign_invalid)} benign IDs failed validation.")

    _write_list(os.path.join(out_dir, "malicious_ids.txt"), malicious_valid)
    _write_list(os.path.join(out_dir, "benign_ids.txt"), benign_valid)
    if mixed_valid:
        _write_list(os.path.join(out_dir, "mixed_ids.txt"), mixed_valid)

    label_rows: List[Dict[str, str]] = []
    for ext_id in malicious_valid:
        label_rows.append({"extension_id": ext_id, "label": "1", "source": "malicious"})
    for ext_id in benign_valid:
        label_rows.append({"extension_id": ext_id, "label": "0", "source": "benign"})
    for ext_id in mixed_valid:
        label_rows.append({"extension_id": ext_id, "label": "0.5", "source": "mixed"})

    labels_path = os.path.join(out_dir, "extension_labels.csv")
    _write_labels_csv(labels_path, label_rows)

    template_path = os.path.join(out_dir, "unified_features_template.csv")
    _write_feature_template(template_path)

    print("\nOutputs:")
    print(f"- {labels_path}")
    print(f"- {template_path}")
    print(f"- {os.path.join(out_dir, 'malicious_ids.txt')}")
    print(f"- {os.path.join(out_dir, 'benign_ids.txt')}")
    if mixed_valid:
        print(f"- {os.path.join(out_dir, 'mixed_ids.txt')}")


if __name__ == "__main__":
    main()
