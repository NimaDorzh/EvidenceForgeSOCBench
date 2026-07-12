"""Stable SHA-256 signatures for dataset contamination tracking."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from evidenceforge.utils.paths import safe_write_text

MANIFEST_FILENAME = "MANIFEST.json"


def file_sha256(path: Path) -> str:
    """Return SHA-256 hex digest of file bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_manifest(dataset_root: Path) -> dict[str, Any]:
    """Build a manifest mapping relative artifact paths to SHA-256 digests."""
    dataset_root = dataset_root.resolve()
    file_hashes: dict[str, str] = {}

    for path in sorted(dataset_root.rglob("*")):
        if not path.is_file():
            continue
        if path.name == MANIFEST_FILENAME and path.parent == dataset_root:
            continue
        rel = path.relative_to(dataset_root).as_posix()
        file_hashes[rel] = file_sha256(path)

    aggregate_source = "\n".join(f"{rel}:{digest}" for rel, digest in sorted(file_hashes.items()))
    dataset_hash = hashlib.sha256(aggregate_source.encode("utf-8")).hexdigest()

    return {
        "schema_version": 1,
        "dataset_root": str(dataset_root),
        "dataset_sha256": dataset_hash,
        "files": file_hashes,
    }


def write_manifest(dataset_root: Path) -> Path:
    """Write ``MANIFEST.json`` at the dataset root and return its path."""
    dataset_root = dataset_root.resolve()
    manifest = build_manifest(dataset_root)
    out_path = dataset_root / MANIFEST_FILENAME
    safe_write_text(
        out_path,
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return out_path
