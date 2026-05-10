"""Build a manifest/code feature dataset from CRX archives."""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import struct
import sys
import zipfile
from pathlib import Path
from typing import Dict, Iterable, Tuple

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.c1.features import extract_manifest_features


CRX_MAGIC = b"Cr24"


def _read_uint32_le(data: bytes, offset: int) -> int:
    return struct.unpack("<I", data[offset : offset + 4])[0]


def _crx_to_zip_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if data[:4] != CRX_MAGIC:
        raise ValueError("Missing CRX magic header")

    version = _read_uint32_le(data, 4)
    if version == 2:
        pub_len = _read_uint32_le(data, 8)
        sig_len = _read_uint32_le(data, 12)
        zip_start = 16 + pub_len + sig_len
    elif version == 3:
        header_len = _read_uint32_le(data, 8)
        zip_start = 12 + header_len
    else:
        raise ValueError(f"Unsupported CRX version: {version}")

    return data[zip_start:]


def _extract_manifest_and_source(path: Path, max_chars: int = 200_000) -> Tuple[dict, str]:
    zip_bytes = _crx_to_zip_bytes(path)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        names = archive.namelist()
        manifest_name = next((n for n in names if n.lower().endswith("manifest.json")), None)
        if not manifest_name:
            raise ValueError("manifest.json not found")

        manifest_raw = archive.read(manifest_name)
        manifest = json.loads(manifest_raw.decode("utf-8", errors="ignore"))

        parts = []
        total = 0
        for name in names:
            if not name.lower().endswith(".js"):
                continue
            try:
                content = archive.read(name).decode("utf-8", errors="ignore")
            except Exception:
                continue
            if not content:
                continue
            remaining = max_chars - total
            if remaining <= 0:
                break
            if len(content) > remaining:
                content = content[:remaining]
            parts.append(content)
            total += len(content)

    return manifest, "\n".join(parts)


def _iter_crx_files(directory: Path) -> Iterable[Path]:
    for entry in directory.iterdir():
        if entry.is_file():
            yield entry


def _write_rows(
    writer: csv.DictWriter,
    paths: Iterable[Path],
    label: int,
    stats: Dict[str, int],
) -> None:
    for path in paths:
        stats["total"] += 1
        try:
            manifest, source = _extract_manifest_and_source(path)
            features = extract_manifest_features(manifest, source)
            row = {**features, "label": label}
            writer.writerow(row)
            stats["written"] += 1
        except Exception:
            stats["skipped"] += 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Build manifest feature dataset from CRX files.")
    parser.add_argument(
        "--benign-dir",
        default=os.path.join("core", "c1", "data", "GoogleChromeExtension", "benign", "benign"),
        help="Directory containing benign CRX files",
    )
    parser.add_argument(
        "--malware-dir",
        default=os.path.join("core", "c1", "data", "GoogleChromeExtension", "malware", "malware"),
        help="Directory containing malware CRX files",
    )
    parser.add_argument(
        "--output",
        default=os.path.join("core", "c1", "data", "manifest_dataset.csv"),
        help="Output CSV path",
    )
    args = parser.parse_args()

    benign_dir = Path(args.benign_dir)
    malware_dir = Path(args.malware_dir)

    features = extract_manifest_features({}, "")
    fieldnames = list(features.keys()) + ["label"]

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        benign_stats = {"total": 0, "written": 0, "skipped": 0}
        malware_stats = {"total": 0, "written": 0, "skipped": 0}

        _write_rows(writer, _iter_crx_files(benign_dir), 0, benign_stats)
        _write_rows(writer, _iter_crx_files(malware_dir), 1, malware_stats)

    print(f"Saved dataset to: {args.output}")
    print(f"Benign - total: {benign_stats['total']}, written: {benign_stats['written']}, skipped: {benign_stats['skipped']}")
    print(f"Malware - total: {malware_stats['total']}, written: {malware_stats['written']}, skipped: {malware_stats['skipped']}")


if __name__ == "__main__":
    main()
