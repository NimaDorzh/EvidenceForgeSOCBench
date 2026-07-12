"""Tests for dataset export, DP2 gate, integrity signatures, and build CLI."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from socbench.export_agent import (
    DP2_STRIPPED_FIELDS,
    export_agent_tree,
    find_dp2_violations,
    strip_dp2_fields,
)
from socbench.export_dataset import DatasetBuildConfig, build_dataset
from socbench.integrity.signatures import MANIFEST_FILENAME, build_manifest
from socbench.sources import build_sources_from_file
from socbench.sources.models import SourceBuildConfig
from socbench.stage.bucketize import bucketize_bundle
from socbench.validate import validate_dataset

REPO_ROOT = Path(__file__).resolve().parents[2]
COLONIAL_SCENARIO = REPO_ROOT / "scenarios" / "colonial-pipeline" / "scenario.yaml"
COLONIAL_EVENTS = (
    REPO_ROOT / "scenarios" / "colonial-pipeline" / "grader" / "canonical_events.ndjson"
)
COLONIAL_WINDOW_START = "2024-06-03T08:00:00Z"
EXPORT_AGENT_PATH = REPO_ROOT / "src" / "socbench" / "export_agent.py"


def _colonial_config(**overrides: object) -> SourceBuildConfig:
    base = {
        "seed": 42,
        "window_start": COLONIAL_WINDOW_START,
        "stage_minutes": 30,
    }
    base.update(overrides)
    return SourceBuildConfig.model_validate(base)


def _load_ndjson(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _build_staged_agent_with_grader_fields(tmp_path: Path) -> Path:
    """Build a staged agent tree that intentionally contains every DP2 field."""
    bundle = tmp_path / "bundle"
    data_root = bundle / "data"
    grader_root = bundle / "grader"
    grader_root.mkdir(parents=True)
    events_dst = grader_root / "canonical_events.ndjson"
    events_dst.write_text(COLONIAL_EVENTS.read_text(encoding="utf-8"), encoding="utf-8")
    build_sources_from_file(events_dst, data_root, _colonial_config())
    bucketize_bundle(
        bundle,
        window_start=COLONIAL_WINDOW_START,
        agent_root=bundle / "agent_raw",
    )
    return bundle / "agent_raw"


def _seed_dp2_fields(agent_raw: Path) -> None:
    """Inject all DP2 fields into the first SIEM alert so absence tests are meaningful."""
    alerts_path = agent_raw / "stage_00" / "data" / "siem" / "alerts.ndjson"
    records = _load_ndjson(alerts_path)
    assert records, "expected at least one SIEM alert in stage_00"
    poisoned = dict(records[0])
    poisoned.update(
        {
            "phase": "impact",
            "attack": ["T1486"],
            "actor": "attacker",
            "evidence_id": "EVID-dp2-test",
            "observed_by": ["siem"],
            "__grader_metadata": {
                "linked_evidence_ids": ["EVID-dp2-test"],
                "latency_applied_ms": 1234,
                "template_id": "dp2-test",
            },
            "min_stage_gate": 99,
        }
    )
    records[0] = poisoned
    lines = [json.dumps(record, sort_keys=True) for record in records]
    alerts_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_export_agent_module_does_not_import_truth() -> None:
    tree = ast.parse(EXPORT_AGENT_PATH.read_text(encoding="utf-8"), filename=str(EXPORT_AGENT_PATH))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert not any(module.startswith("socbench.truth") for module in imported)


def test_strip_dp2_fields_removes_all_configured_keys() -> None:
    payload = {field: f"value-{field}" for field in DP2_STRIPPED_FIELDS}
    payload["host"] = "FS-01"
    cleaned = strip_dp2_fields(payload)
    assert set(cleaned.keys()) == {"host"}
    for field in DP2_STRIPPED_FIELDS:
        assert field not in cleaned


def test_dp2_gate_strips_injected_fields_from_agent_export(tmp_path: Path) -> None:
    """Prove the DP2 mechanism removes fields that were present before export."""
    agent_raw = _build_staged_agent_with_grader_fields(tmp_path)
    _seed_dp2_fields(agent_raw)

    pre_export = _load_ndjson(agent_raw / "stage_00" / "data" / "siem" / "alerts.ndjson")[0]
    assert set(DP2_STRIPPED_FIELDS) <= set(pre_export.keys())

    export_agent_tree(agent_raw, tmp_path / "agent")
    post_export = _load_ndjson(tmp_path / "agent" / "stage_00" / "data" / "siem" / "alerts.ndjson")[0]
    for field in DP2_STRIPPED_FIELDS:
        assert field not in post_export, f"DP2 gate failed to strip {field!r}"


def test_dp2_gate_detects_injected_fields_when_export_disabled(tmp_path: Path) -> None:
    """Negative control: violations must be detected if export gate is bypassed."""
    agent_raw = _build_staged_agent_with_grader_fields(tmp_path)
    _seed_dp2_fields(agent_raw)
    violations = find_dp2_violations(agent_raw)
    assert violations, "expected DP2 violations when grader fields remain in agent tree"


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_dp2_gate_no_grader_fields_in_agent(tmp_path: Path) -> None:
    """End-to-end DP2 acceptance: full build must leave agent tree clean."""
    out_dir = tmp_path / "dataset"
    build_dataset(
        DatasetBuildConfig(
            scenario_path=COLONIAL_SCENARIO,
            output_dir=out_dir,
            seed=42,
            window_start=COLONIAL_WINDOW_START,
            stream_by_stage=True,
        )
    )

    violations = find_dp2_violations(out_dir / "agent")
    assert violations == [], "DP2 violations:\n" + "\n".join(violations)

    for path in (out_dir / "agent").rglob("*"):
        rel = path.relative_to(out_dir / "agent").as_posix()
        assert not rel.startswith("grader/"), f"grader path leaked into agent: {rel}"
        assert path.name != "canonical_events.ndjson", "canonical events leaked into agent"


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_build_is_deterministic_via_manifest(tmp_path: Path) -> None:
    first = tmp_path / "run1"
    second = tmp_path / "run2"
    config = DatasetBuildConfig(
        scenario_path=COLONIAL_SCENARIO,
        output_dir=first,
        seed=42,
        window_start=COLONIAL_WINDOW_START,
        stream_by_stage=True,
    )
    build_dataset(config)
    build_dataset(
        DatasetBuildConfig(
            scenario_path=COLONIAL_SCENARIO,
            output_dir=second,
            seed=42,
            window_start=COLONIAL_WINDOW_START,
            stream_by_stage=True,
        )
    )

    manifest1 = json.loads((first / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    manifest2 = json.loads((second / MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert manifest1["dataset_sha256"] == manifest2["dataset_sha256"]
    assert manifest1["files"] == manifest2["files"]


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_manifest_contains_per_file_and_dataset_hashes(tmp_path: Path) -> None:
    out_dir = tmp_path / "dataset"
    build_dataset(
        DatasetBuildConfig(
            scenario_path=COLONIAL_SCENARIO,
            output_dir=out_dir,
            seed=42,
            window_start=COLONIAL_WINDOW_START,
        )
    )
    manifest = build_manifest(out_dir)
    assert manifest["dataset_sha256"]
    assert manifest["files"]
    assert "agent/topology.json" in manifest["files"]
    assert any(path.startswith("grader/") for path in manifest["files"])


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_mutated_build_passes_dp2_and_validate(tmp_path: Path) -> None:
    out_dir = tmp_path / "dataset"
    build_dataset(
        DatasetBuildConfig(
            scenario_path=COLONIAL_SCENARIO,
            output_dir=out_dir,
            seed=42,
            window_start=COLONIAL_WINDOW_START,
            stream_by_stage=True,
            mutate_seed=99,
        )
    )
    assert find_dp2_violations(out_dir / "agent") == []
    result = validate_dataset(out_dir)
    assert result.ok, result.errors
