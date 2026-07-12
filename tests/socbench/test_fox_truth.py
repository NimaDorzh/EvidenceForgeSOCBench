"""Tests for Fox truth projection (o1_scale / o2_type / o3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from socbench.capture.models import CanonicalEvent
from socbench.truth.common import (
    AUTH_BURST_MIN_EVENTS,
    AUTH_BURST_WINDOW_MINUTES,
    RANSOMWARE_PRECURSOR_MARKERS,
    auth_burst_detected,
    build_host_interaction_graph,
    classify_scale_label,
    classify_type_label,
    distinct_precursor_categories,
    parse_ts,
    precursor_categories_for_event,
    stage_of,
)
from socbench.truth.fox import build_fox_manifest, build_fox_manifest_from_file

REPO_ROOT = Path(__file__).resolve().parents[2]
COLONIAL_EVENTS = (
    REPO_ROOT / "scenarios" / "colonial-pipeline" / "grader" / "canonical_events.ndjson"
)
COLONIAL_WINDOW_START = "2024-06-03T08:00:00Z"


def _event(
    *,
    evidence_id: str,
    ts: str,
    host: str,
    kind: str = "process",
    attack: list[str] | None = None,
    fields: dict | None = None,
) -> CanonicalEvent:
    return CanonicalEvent(
        evidence_id=evidence_id,
        ts=ts,
        host=host,
        actor="attacker",
        kind=kind,
        attack=attack or [],
        fields=fields or {},
        record_id=f"{evidence_id}#0",
    )


def test_ransomware_precursor_markers_cover_expected_categories() -> None:
    categories = {marker.category for marker in RANSOMWARE_PRECURSOR_MARKERS}
    assert categories == {"T1569.002", "T1021.002", "event_7045"}


def test_precursor_categories_for_service_installed() -> None:
    event = _event(
        evidence_id="EVID-svc",
        ts="2024-01-01T00:00:00Z",
        host="FS-01",
        kind="service_installed",
        fields={"service_name": "PSEXESVC"},
    )
    assert precursor_categories_for_event(event) == {"T1569.002", "event_7045"}


def test_classify_scale_isolated_single_host() -> None:
    label = classify_scale_label({"HOST-A"}, set(), auth_burst=False)
    assert label == "isolated"


def test_classify_scale_localized_pair_with_edge() -> None:
    label = classify_scale_label(
        {"HOST-A", "HOST-B"},
        {("HOST-A", "HOST-B")},
        auth_burst=False,
    )
    assert label == "localized"


def test_classify_scale_campaign_for_three_hosts() -> None:
    label = classify_scale_label(
        {"HOST-A", "HOST-B", "HOST-C"},
        {("HOST-A", "HOST-B")},
        auth_burst=False,
    )
    assert label == "campaign_scale"


def test_classify_scale_campaign_for_auth_burst() -> None:
    label = classify_scale_label({"HOST-A", "HOST-B"}, set(), auth_burst=True)
    assert label == "campaign_scale"


def test_auth_burst_requires_two_hosts_and_min_events() -> None:
    events = [
        _event(
            evidence_id="EVID-1",
            ts="2024-01-01T00:00:00Z",
            host="FS-01",
            kind="logon",
            attack=["T1021.002"],
            fields={"source_ip": "10.0.0.1"},
        ),
        _event(
            evidence_id="EVID-2",
            ts="2024-01-01T00:01:00Z",
            host="FS-02",
            kind="logon",
            attack=["T1021.002"],
            fields={"source_ip": "10.0.0.1"},
        ),
        _event(
            evidence_id="EVID-3",
            ts="2024-01-01T00:02:00Z",
            host="FS-01",
            kind="explicit_credentials",
            attack=["T1021.002"],
        ),
    ]
    assert auth_burst_detected(events) is True


def test_build_host_interaction_graph_remote_exec_edge() -> None:
    events = [
        _event(
            evidence_id="EVID-src",
            ts="2024-01-01T00:00:00Z",
            host="WKS-OPS-01",
            fields={
                "command_line": r"PsExec.exe \\FS-01 -accepteula cmd.exe",
            },
            attack=["T1569.002"],
        ),
        _event(
            evidence_id="EVID-dst",
            ts="2024-01-01T00:01:00Z",
            host="FS-01",
            kind="service_installed",
            attack=["T1569.002"],
            fields={"service_name": "PSEXESVC"},
        ),
    ]
    hosts, edges, _metadata = build_host_interaction_graph(events)
    assert hosts == {"FS-01", "WKS-OPS-01"}
    assert ("FS-01", "WKS-OPS-01") in edges


def test_classify_type_label_rules() -> None:
    two_markers = [
        _event(
            evidence_id="EVID-b",
            ts="2024-01-01T00:01:00Z",
            host="FS-01",
            kind="service_installed",
            fields={"service_name": "PSEXESVC"},
        ),
    ]
    assert classify_type_label(two_markers, scale_label="localized") == "ransomware_like"
    assert distinct_precursor_categories(two_markers) == {"T1569.002", "event_7045"}

    one_marker = [
        _event(
            evidence_id="EVID-c",
            ts="2024-01-01T00:00:00Z",
            host="WKS-01",
            fields={"command_line": "PsExec.exe \\\\FS-01 -accepteula cmd.exe"},
        )
    ]
    assert classify_type_label(one_marker, scale_label="isolated") == "uncertain"
    assert classify_type_label(one_marker, scale_label="campaign_scale") == "non_ransom_coordinated"

    coordinated_no_precursors = [
        _event(
            evidence_id="EVID-d",
            ts="2024-01-01T00:00:00Z",
            host="FS-01",
            attack=["T1048"],
        )
    ]
    assert (
        classify_type_label(coordinated_no_precursors, scale_label="campaign_scale") == "uncertain"
    )


def test_build_fox_manifest_cumulative_o3() -> None:
    events = [
        _event(
            evidence_id="EVID-first",
            ts="2024-01-01T00:05:00Z",
            host="VPN-GW-01",
            kind="connection",
            attack=["T1133"],
        ),
        _event(
            evidence_id="EVID-ransom",
            ts="2024-01-01T01:05:00Z",
            host="FS-01",
            attack=["T1486"],
            fields={"command_line": "darkside_svc.exe --encrypt \\\\FS-01\\Finance"},
        ),
    ]
    manifest = build_fox_manifest(events, window_start="2024-01-01T00:00:00Z", stage_minutes=30)
    stage_zero = manifest["stages"][0]["o3"]
    stage_two = manifest["stages"][2]["o3"]
    assert stage_zero["first_affected_host"] == "VPN-GW-01"
    assert stage_zero["first_ransomware_evidence_id"] is None
    assert stage_two["first_ransomware_host"] == "FS-01"
    assert stage_two["first_ransomware_evidence_id"] == "EVID-ransom"


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_colonial_fox_manifest_progression() -> None:
    import yaml

    from evidenceforge.models.scenario import Scenario
    from socbench.capture.canonical_events import build_canonical_events

    scenario_path = REPO_ROOT / "scenarios" / "colonial-pipeline" / "scenario.yaml"
    bundle_dir = REPO_ROOT / "scenarios" / "colonial-pipeline"
    scenario = Scenario.model_validate(yaml.safe_load(scenario_path.read_text(encoding="utf-8")))
    events = build_canonical_events(bundle_dir, scenario, seed=42)
    manifest = build_fox_manifest(
        events,
        window_start=COLONIAL_WINDOW_START,
        stage_minutes=30,
    )
    by_stage = {entry["stage"]: entry for entry in manifest["stages"]}

    stage0 = by_stage[0]["o1_scale"]
    assert stage0["scale_label"] == "campaign_scale"
    assert stage0["affected_hosts"] == ["VPN-GW-01", "WKS-OPS-01"]
    assert stage0["host_graph"]["edges"] == []

    stage1 = by_stage[1]["o1_scale"]
    assert stage1["scale_label"] == "campaign_scale"
    assert "FS-01" in stage1["affected_hosts"]

    stage1_type = by_stage[1]["o2_type"]
    assert stage1_type["type_label"] == "ransomware_like"
    assert stage1_type["distinct_precursor_count"] >= 2

    early_type = by_stage[0]["o2_type"]
    assert early_type["type_label"] == "uncertain"

    assumptions = manifest["assumptions"]
    assert assumptions["auth_burst_min_events"] == AUTH_BURST_MIN_EVENTS
    assert assumptions["auth_burst_window_minutes"] == AUTH_BURST_WINDOW_MINUTES


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_colonial_stage_of_alignment() -> None:
    events = build_fox_manifest_from_file(COLONIAL_EVENTS, window_start=COLONIAL_WINDOW_START)[
        "stages"
    ]
    assert events, "expected staged fox output"
    assert events[0]["stage"] == 0
    assert stage_of("2024-06-03T08:02:45Z", parse_ts(COLONIAL_WINDOW_START)) == 0
    assert stage_of("2024-06-03T08:33:35Z", parse_ts(COLONIAL_WINDOW_START)) == 1


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_fox_ignores_ground_truth_labels() -> None:
    import yaml

    from evidenceforge.models.scenario import Scenario
    from socbench.capture.canonical_events import build_canonical_events

    scenario_path = REPO_ROOT / "scenarios" / "colonial-pipeline" / "scenario.yaml"
    bundle_dir = REPO_ROOT / "scenarios" / "colonial-pipeline"
    scenario = Scenario.model_validate(yaml.safe_load(scenario_path.read_text(encoding="utf-8")))
    events = build_canonical_events(bundle_dir, scenario, seed=42)
    baseline = build_fox_manifest(events, window_start=COLONIAL_WINDOW_START, stage_minutes=30)

    stripped = [
        event.model_copy(update={"phase": None, "attack": [], "actor": ""}) for event in events
    ]
    redacted = build_fox_manifest(
        stripped,
        window_start=COLONIAL_WINDOW_START,
        stage_minutes=30,
    )

    assert redacted["stages"] == baseline["stages"]


def test_fox_skips_empty_early_stages() -> None:
    """Early empty stages must not crash when window_start precedes all events."""
    events = [
        _event(
            evidence_id="EVID-late",
            ts="2024-01-15T15:29:39Z",
            host="MUSIC-SRV-01",
            kind="connection",
            fields={"source_ip": "203.0.113.45", "dst_ip": "10.10.30.50"},
        ),
        _event(
            evidence_id="EVID-process",
            ts="2024-01-15T15:30:05Z",
            host="MUSIC-SRV-01",
            fields={"command_line": "bash -c whoami"},
        ),
    ]
    early_origin = "2024-01-15T05:00:00Z"
    manifest = build_fox_manifest(events, window_start=early_origin, stage_minutes=30)

    assert manifest["stages"]
    assert manifest["stages"][0]["o1_scale"]["scale_label"] is None
    assert manifest["stages"][-1]["o3"]["first_affected_host"] == "MUSIC-SRV-01"
    assert manifest["stages"][-1]["o3"]["first_affected_evidence_id"] == "EVID-late"


def test_fox_empty_early_stages_matches_late_stage_labels() -> None:
    """Manifest with early empty prefix should match infer-window baseline labels."""
    events = [
        _event(
            evidence_id="EVID-a",
            ts="2024-01-15T15:29:39Z",
            host="MUSIC-SRV-01",
            kind="connection",
            fields={"source_ip": "203.0.113.45", "dst_ip": "10.10.30.50"},
        ),
    ]
    baseline = build_fox_manifest(events)
    with_early_prefix = build_fox_manifest(
        events,
        window_start="2024-01-15T05:00:00Z",
        stage_minutes=30,
    )
    assert with_early_prefix["stages"][-1]["o1_scale"] == baseline["stages"][-1]["o1_scale"]
    assert with_early_prefix["stages"][-1]["o2_type"] == baseline["stages"][-1]["o2_type"]
