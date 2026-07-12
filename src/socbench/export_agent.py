"""Agent-side dataset export with DP2 field stripping.

This module must not import ``socbench.truth`` so ground-truth logic cannot leak
into agent exports through shared code paths.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from evidenceforge.utils.paths import safe_write_text

DP2_STRIPPED_FIELDS: frozenset[str] = frozenset(
    {
        "phase",
        "attack",
        "actor",
        "evidence_id",
        "observed_by",
        "__grader_metadata",
        "min_stage_gate",
    }
)

GRADER_ONLY_AGENT_FILENAMES: frozenset[str] = frozenset({"canonical_events.ndjson"})


def strip_dp2_fields(record: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *record* with DP2 grader-only top-level keys removed."""
    return {key: value for key, value in record.items() if key not in DP2_STRIPPED_FIELDS}


def export_agent_tree(source_root: Path, dest_root: Path) -> None:
    """Copy staged agent tree to *dest_root*, applying the DP2 gate on every NDJSON row."""
    source_root = source_root.resolve()
    dest_root = dest_root.resolve()
    if dest_root.exists():
        shutil.rmtree(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)

    for path in sorted(source_root.rglob("*")):
        rel = path.relative_to(source_root)
        if path.is_dir():
            continue
        if rel.name in GRADER_ONLY_AGENT_FILENAMES:
            continue
        if "grader" in rel.parts:
            continue

        out_path = dest_root / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".ndjson":
            records = _load_ndjson(path)
            cleaned = [strip_dp2_fields(record) for record in records]
            _write_ndjson(out_path, cleaned)
        else:
            shutil.copy2(path, out_path)


def iter_agent_ndjson_records(agent_root: Path) -> list[tuple[Path, dict[str, Any]]]:
    """Yield every NDJSON record under *agent_root* with its source path."""
    agent_root = agent_root.resolve()
    found: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(agent_root.rglob("*.ndjson")):
        for record in _load_ndjson(path):
            found.append((path, record))
    return found


def find_dp2_violations(agent_root: Path) -> list[str]:
    """Return human-readable DP2 violations found under *agent_root*."""
    violations: list[str] = []
    agent_root = agent_root.resolve()

    for path in sorted(agent_root.rglob("*")):
        rel = path.relative_to(agent_root).as_posix()
        if "grader" in path.parts or rel.startswith("grader/"):
            violations.append(f"grader path leaked into agent tree: {rel}")
        if path.name in GRADER_ONLY_AGENT_FILENAMES:
            violations.append(f"grader-only file present in agent tree: {rel}")

    for path, record in iter_agent_ndjson_records(agent_root):
        rel = path.relative_to(agent_root).as_posix()
        for field in DP2_STRIPPED_FIELDS:
            if field in record:
                violations.append(f"{rel}: forbidden field {field!r}")
    return violations


def _load_ndjson(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        payload = json.loads(stripped)
        if isinstance(payload, dict):
            records.append(payload)
    return records


def _write_ndjson(path: Path, records: list[dict[str, Any]]) -> None:
    lines = [json.dumps(record, sort_keys=True) for record in records]
    payload = "\n".join(lines)
    if payload:
        payload += "\n"
    safe_write_text(path, payload, encoding="utf-8")
