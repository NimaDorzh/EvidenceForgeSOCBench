"""Cross-module truth projector consistency checks (step 3 DoD)."""

from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from evidenceforge.models.scenario import Scenario
from socbench.capture.canonical_events import build_canonical_events
from socbench.truth.common import index_by_evidence_id, load_canonical_events, resolve_evidence_id
from socbench.truth.fox import FOX_MANIFEST_FILENAME, build_fox_manifest_from_file
from socbench.truth.goat import GOAT_MANIFEST_FILENAME, build_goat_manifest_from_file
from socbench.truth.mouse import MOUSE_MANIFEST_FILENAME, build_mouse_manifest_from_file
from socbench.truth.panda import PANDA_MANIFEST_FILENAME, build_panda_manifest_from_file
from socbench.truth.tiger import TIGER_MANIFEST_FILENAME, build_tiger_manifest, build_tiger_manifest_from_file

REPO_ROOT = Path(__file__).resolve().parents[2]
TRUTH_DIR = REPO_ROOT / "src" / "socbench" / "truth"
COLONIAL_BUNDLE = REPO_ROOT / "scenarios" / "colonial-pipeline"
COLONIAL_SCENARIO = COLONIAL_BUNDLE / "scenario.yaml"
COLONIAL_EVENTS = COLONIAL_BUNDLE / "grader" / "canonical_events.ndjson"
COLONIAL_WINDOW_START = "2024-06-03T08:00:00Z"

TRUTH_MANIFEST_FILENAMES = (
    FOX_MANIFEST_FILENAME,
    GOAT_MANIFEST_FILENAME,
    MOUSE_MANIFEST_FILENAME,
    TIGER_MANIFEST_FILENAME,
    PANDA_MANIFEST_FILENAME,
)

_EVIDENCE_ID_KEYS = frozenset(
    {
        "evidence_id",
        "evidence_ids",
        "supporting_evidence_ids",
        "forbidden_evidence_ids",
        "first_affected_evidence_id",
        "first_ransomware_evidence_id",
    }
)

_ALLOWED_IMPORT_PREFIXES = (
    "socbench.truth.common",
    "socbench.truth.errors",
    "socbench.capture",
    "socbench.stage",
    "evidenceforge.utils",
)

_FORBIDDEN_TRUTH_MODULES = frozenset(
    {
        "socbench.truth.fox",
        "socbench.truth.goat",
        "socbench.truth.mouse",
        "socbench.truth.tiger",
        "socbench.truth.panda",
    }
)


def _collect_evidence_id_values(value: Any, *, key: str | None = None) -> set[str]:
    """Recursively collect evidence_id strings from manifest JSON."""
    found: set[str] = set()
    if key in _EVIDENCE_ID_KEYS:
        if isinstance(value, str) and value.startswith("EVID-"):
            found.add(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.startswith("EVID-"):
                    found.add(item)
                else:
                    found.update(_collect_evidence_id_values(item))
        elif isinstance(value, dict):
            for nested_key, nested_value in value.items():
                found.update(_collect_evidence_id_values(nested_value, key=nested_key))
        return found

    if isinstance(value, dict):
        for nested_key, nested_value in value.items():
            found.update(_collect_evidence_id_values(nested_value, key=nested_key))
    elif isinstance(value, list):
        for item in value:
            found.update(_collect_evidence_id_values(item))
    return found


def _imported_module_names(tree: ast.Module) -> list[str]:
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    return modules


def _is_allowed_import(module: str) -> bool:
    root = module.split(".")[0]
    if root in sys.stdlib_module_names:
        return True
    return any(
        module == prefix or module.startswith(f"{prefix}.") for prefix in _ALLOWED_IMPORT_PREFIXES
    )


def _build_all_manifests(events_path: Path) -> dict[str, dict[str, Any]]:
    return {
        FOX_MANIFEST_FILENAME: build_fox_manifest_from_file(
            events_path,
            window_start=COLONIAL_WINDOW_START,
        ),
        GOAT_MANIFEST_FILENAME: build_goat_manifest_from_file(
            events_path,
            window_start=COLONIAL_WINDOW_START,
        ),
        MOUSE_MANIFEST_FILENAME: build_mouse_manifest_from_file(events_path),
        TIGER_MANIFEST_FILENAME: build_tiger_manifest_from_file(events_path),
        PANDA_MANIFEST_FILENAME: build_panda_manifest_from_file(
            events_path,
            window_start=COLONIAL_WINDOW_START,
        ),
    }


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_all_manifest_evidence_ids_resolve() -> None:
    events = load_canonical_events(COLONIAL_EVENTS)
    events_by_id = index_by_evidence_id(events)
    manifests = _build_all_manifests(COLONIAL_EVENTS)

    unresolved: list[tuple[str, str]] = []
    for filename, manifest in manifests.items():
        for evidence_id in sorted(_collect_evidence_id_values(manifest)):
            try:
                resolve_evidence_id(evidence_id, events_by_id)
            except Exception:
                unresolved.append((filename, evidence_id))

    assert not unresolved, f"Unresolved manifest evidence_ids: {unresolved}"


def test_no_truth_module_imports_another() -> None:
    violations: list[str] = []
    skip_files = {"common.py", "__init__.py"}
    for path in sorted(TRUTH_DIR.glob("*.py")):
        if path.name in skip_files:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for module in _imported_module_names(tree):
            if module in _FORBIDDEN_TRUTH_MODULES:
                violations.append(f"{path.name}: forbidden cross-truth import {module!r}")
                continue
            if not _is_allowed_import(module):
                violations.append(f"{path.name}: disallowed import {module!r}")

    assert not violations, "Truth module import violations:\n" + "\n".join(violations)


@pytest.mark.skipif(not COLONIAL_SCENARIO.is_file(), reason="colonial scenario missing")
def test_forbidden_evidence_ids_empty_source_safe() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_BUNDLE, scenario, seed=42)
    manifest = build_tiger_manifest(events)

    assert manifest["forbidden_evidence_ids"] == []
    assert not any(event.kind == "helpdesk" for event in events)


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_truth_build_writes_five_manifests_deterministically(tmp_path: Path) -> None:
    """Unified build produces exactly five task manifests with stable hashes."""
    out_dir = tmp_path / "grader"
    out_dir.mkdir()

    def digest_manifests(directory: Path) -> dict[str, str]:
        return {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in TRUTH_MANIFEST_FILENAMES
        }

    manifests_run1 = _build_all_manifests(COLONIAL_EVENTS)
    for name, payload in manifests_run1.items():
        serialized = json.dumps(payload, indent=2, sort_keys=False) + "\n"
        (out_dir / name).write_bytes(serialized.encode("utf-8"))

    json_files = sorted(path.name for path in out_dir.glob("*.json"))
    assert json_files == sorted(TRUTH_MANIFEST_FILENAMES)

    digests_run1 = digest_manifests(out_dir)

    manifests_run2 = _build_all_manifests(COLONIAL_EVENTS)
    for name, payload in manifests_run2.items():
        assert hashlib.sha256(
            (json.dumps(payload, indent=2, sort_keys=False) + "\n").encode()
        ).hexdigest() == digests_run1[name]

    # Order of task invocation must not affect output (reverse build order).
    reverse_manifests = {
        PANDA_MANIFEST_FILENAME: build_panda_manifest_from_file(
            COLONIAL_EVENTS,
            window_start=COLONIAL_WINDOW_START,
        ),
        TIGER_MANIFEST_FILENAME: build_tiger_manifest_from_file(COLONIAL_EVENTS),
        MOUSE_MANIFEST_FILENAME: build_mouse_manifest_from_file(COLONIAL_EVENTS),
        GOAT_MANIFEST_FILENAME: build_goat_manifest_from_file(
            COLONIAL_EVENTS,
            window_start=COLONIAL_WINDOW_START,
        ),
        FOX_MANIFEST_FILENAME: build_fox_manifest_from_file(
            COLONIAL_EVENTS,
            window_start=COLONIAL_WINDOW_START,
        ),
    }
    for name, payload in reverse_manifests.items():
        assert hashlib.sha256(
            (json.dumps(payload, indent=2, sort_keys=False) + "\n").encode()
        ).hexdigest() == digests_run1[name]
