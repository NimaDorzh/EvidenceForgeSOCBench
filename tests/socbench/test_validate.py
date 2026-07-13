"""Tests for dataset validate.py consistency checks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from socbench.export_dataset import DatasetBuildConfig, build_dataset
from socbench.validate import (
    validate_agent_stage_count_aligned,
    validate_claim_evidence_ids_resolve,
    validate_causality_respects_stage_order,
    validate_dataset,
    validate_dp2_agent_clean,
    validate_helpdesk_not_positive_evidence,
    validate_tiger_verifiable_edges_reconstructible,
)
from tests.socbench.colonial_fixtures import COLONIAL_SCENARIO, COLONIAL_WINDOW_START


@pytest.fixture(name="built_dataset")
def fixture_built_dataset(tmp_path: Path) -> Path:
    if not COLONIAL_SCENARIO.is_file():
        pytest.skip("colonial scenario missing")
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
    return out_dir


def test_validate_claim_evidence_ids_resolve_passes(built_dataset: Path) -> None:
    assert validate_claim_evidence_ids_resolve(built_dataset) == []


def test_validate_helpdesk_not_positive_evidence_passes(built_dataset: Path) -> None:
    assert validate_helpdesk_not_positive_evidence(built_dataset) == []


def test_validate_dp2_agent_clean_passes(built_dataset: Path) -> None:
    assert validate_dp2_agent_clean(built_dataset) == []


def test_validate_causality_respects_stage_order_passes(built_dataset: Path) -> None:
    assert validate_causality_respects_stage_order(built_dataset) == []


def test_validate_agent_stage_count_aligned_passes(built_dataset: Path) -> None:
    assert validate_agent_stage_count_aligned(built_dataset) == []


def test_validate_tiger_verifiable_edges_reconstructible_passes(built_dataset: Path) -> None:
    assert validate_tiger_verifiable_edges_reconstructible(built_dataset) == []


def test_validate_dataset_aggregate_passes(built_dataset: Path) -> None:
    result = validate_dataset(built_dataset)
    assert result.ok, result.errors


def test_validate_dp2_agent_clean_fails_on_poisoned_record(built_dataset: Path) -> None:
    alerts_path = (
        built_dataset
        / "agent"
        / sorted((built_dataset / "agent").glob("stage_*"))[-1]
        / "data"
        / "siem"
        / "alerts.ndjson"
    )
    records = [
        json.loads(line)
        for line in alerts_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert records
    records[0]["__grader_metadata"] = {"linked_evidence_ids": ["EVID-bad"]}
    alerts_path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
        encoding="utf-8",
    )
    errors = validate_dp2_agent_clean(built_dataset)
    assert errors
    assert any("__grader_metadata" in error for error in errors)


def test_validate_claim_resolution_fails_on_missing_evidence_id(built_dataset: Path) -> None:
    fox_path = built_dataset / "grader" / "manifests" / "fox.json"
    manifest = json.loads(fox_path.read_text(encoding="utf-8"))
    manifest["stages"][0]["o3"]["first_affected_evidence_id"] = "EVID-deadbeef"
    fox_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    errors = validate_claim_evidence_ids_resolve(built_dataset)
    assert any("EVID-deadbeef" in error for error in errors)


def test_validate_helpdesk_fails_when_ticket_id_claimed_as_positive_evidence(
    built_dataset: Path,
) -> None:
    """Inject a real helpdesk ticket id into manifest claims; validator must reject it."""
    from socbench.validate import _collect_helpdesk_ticket_ids, _latest_agent_data_root

    agent_data = _latest_agent_data_root(built_dataset)
    assert agent_data is not None
    ticket_ids = _collect_helpdesk_ticket_ids(agent_data)
    assert ticket_ids, "expected helpdesk tickets in built colonial dataset"

    ticket_id = sorted(ticket_ids)[0]
    panda_path = built_dataset / "grader" / "manifests" / "panda.json"
    manifest = json.loads(panda_path.read_text(encoding="utf-8"))
    stage0 = manifest["stages"][0]
    claims = list(stage0.get("supporting_evidence_ids", []))
    claims.append(ticket_id)
    stage0["supporting_evidence_ids"] = claims
    panda_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    errors = validate_helpdesk_not_positive_evidence(built_dataset)
    assert errors, "helpdesk validator must fail when ticket id is a positive claim"
    assert any(ticket_id in error for error in errors)


def test_validate_causality_fails_when_future_evidence_claimed_in_early_stage(
    built_dataset: Path,
) -> None:
    """Stage-0 manifest claim must not reference evidence from a later stage."""
    from socbench.truth.common import load_canonical_events, resolve_window_start, stage_of

    events = load_canonical_events(built_dataset / "grader" / "canonical_events.ndjson")
    origin = resolve_window_start(events, COLONIAL_WINDOW_START)
    late_event = max(events, key=lambda event: stage_of(event.ts, origin))
    late_stage = stage_of(late_event.ts, origin)
    assert late_stage > 0, "need a future-stage event for causality regression"

    panda_path = built_dataset / "grader" / "manifests" / "panda.json"
    manifest = json.loads(panda_path.read_text(encoding="utf-8"))
    stage0 = manifest["stages"][0]
    claims = list(stage0.get("supporting_evidence_ids", []))
    claims.append(late_event.evidence_id)
    stage0["supporting_evidence_ids"] = claims
    panda_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    errors = validate_causality_respects_stage_order(built_dataset)
    assert errors, "causality validator must fail on future-stage evidence in stage 0"
    assert any(late_event.evidence_id in error for error in errors)
    assert any("stage 0" in error for error in errors)


def test_validate_tiger_fails_when_psexec_edge_not_witnessed_in_agent(
    built_dataset: Path,
) -> None:
    """Removing CORR-002 SIEM rows must break psexec verifiable-edge reconstruction."""
    last_stage = sorted((built_dataset / "agent").glob("stage_*"))[-1]
    alerts_path = last_stage / "data" / "siem" / "alerts.ndjson"
    records = [
        json.loads(line)
        for line in alerts_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    filtered = [row for row in records if row.get("rule_id") != "CORR-002"]
    assert len(filtered) < len(records), "expected CORR-002 alerts to remove for tiger regression"
    alerts_path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in filtered) + "\n",
        encoding="utf-8",
    )

    errors = validate_tiger_verifiable_edges_reconstructible(built_dataset)
    assert errors, "tiger validator must fail when psexec SIEM witness rows are removed"
    assert any("psexec_remote_service" in error for error in errors)


def test_validate_dataset_aggregate_fails_when_any_invariant_breaks(built_dataset: Path) -> None:
    """Aggregate validate must surface poisoned DP2 rows through validate_dataset()."""
    alerts_path = (
        built_dataset
        / "agent"
        / sorted((built_dataset / "agent").glob("stage_*"))[-1]
        / "data"
        / "siem"
        / "alerts.ndjson"
    )
    records = [
        json.loads(line)
        for line in alerts_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    records[0]["evidence_id"] = "EVID-leak"
    alerts_path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
        encoding="utf-8",
    )
    result = validate_dataset(built_dataset)
    assert not result.ok
    assert any("evidence_id" in error for error in result.errors)


def test_validate_agent_stage_count_fails_when_agent_stages_exceed_grader(
    tmp_path: Path,
) -> None:
    """Far out-of-window source timestamps must fail stage-depth validation."""
    dataset = tmp_path / "dataset"
    manifests_dir = dataset / "grader" / "manifests"
    manifests_dir.mkdir(parents=True)
    (manifests_dir / "fox.json").write_text(
        json.dumps({"stages": [{"stage": 0}, {"stage": 1}, {"stage": 2}], "stage_minutes": 30})
        + "\n",
        encoding="utf-8",
    )
    (dataset / "grader" / "canonical_events.ndjson").write_text(
        json.dumps(
            {
                "evidence_id": "EVID-abc",
                "ts": "2024-01-01T00:00:00Z",
                "host": "HOST-01",
                "kind": "process",
                "fields": {},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    for stage_index in range(10):
        stage_dir = dataset / "agent" / f"stage_{stage_index:02d}" / "data"
        stage_dir.mkdir(parents=True)

    errors = validate_agent_stage_count_aligned(dataset)
    assert errors
    assert any("derived from max forward source latency" in error for error in errors)


def test_validate_agent_stage_slack_uses_manifest_stage_minutes(tmp_path: Path) -> None:
    """Validator must read stage_minutes from manifests, not assume 30m."""
    from socbench.sources.latency_budget import allowed_agent_stage_slack

    dataset = tmp_path / "dataset"
    manifests_dir = dataset / "grader" / "manifests"
    manifests_dir.mkdir(parents=True)
    stage_minutes = 15
    (manifests_dir / "fox.json").write_text(
        json.dumps({"stages": [{"stage": 0}, {"stage": 1}, {"stage": 2}], "stage_minutes": stage_minutes})
        + "\n",
        encoding="utf-8",
    )
    (dataset / "grader" / "canonical_events.ndjson").write_text(
        json.dumps(
            {
                "evidence_id": "EVID-abc",
                "ts": "2024-01-01T00:00:00Z",
                "host": "HOST-01",
                "kind": "process",
                "fields": {},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    allowed = allowed_agent_stage_slack(stage_minutes)
    grader_stages = 3
    # One stage beyond grader+allowed slack must fail; exactly at boundary must pass.
    for stage_index in range(grader_stages + allowed):
        stage_dir = dataset / "agent" / f"stage_{stage_index:02d}" / "data"
        stage_dir.mkdir(parents=True)
    assert validate_agent_stage_count_aligned(dataset) == []

    overflow = dataset / "agent" / f"stage_{grader_stages + allowed:02d}" / "data"
    overflow.mkdir(parents=True)
    errors = validate_agent_stage_count_aligned(dataset)
    assert errors
    assert str(stage_minutes) in errors[0]
