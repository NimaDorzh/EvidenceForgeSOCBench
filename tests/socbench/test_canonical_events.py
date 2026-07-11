"""Tests for socbench canonical event capture."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from evidenceforge.models.scenario import Scenario
from socbench.capture.canonical_events import (
    build_canonical_events,
    canonical_events_digest,
    format_evidence_id,
    write_canonical_events,
)
from socbench.capture.output_refs import resolve_output_refs
from socbench.capture.scenario_index import build_storyline_index, parse_attack_ids

REPO_ROOT = Path(__file__).resolve().parents[2]
BRANCH_OFFICE_SCENARIO = REPO_ROOT / "scenarios" / "branch-office-example" / "scenario.yaml"
BRANCH_OFFICE_BUNDLE = REPO_ROOT / "output" / "branch-office-test"
RETAIL_SCENARIO = REPO_ROOT / "tests" / "fixtures" / "scenarios" / "retail-store-ftp-attack.yaml"
RETAIL_BUNDLE = REPO_ROOT / "output" / "retail-test"


def _load_scenario(path: Path) -> Scenario:
    return Scenario.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def test_parse_attack_ids_extracts_technique_prefix() -> None:
    assert parse_attack_ids("T1190 - Exploit Public-Facing Application") == ["T1190"]
    assert parse_attack_ids("T1087.001 - Account Discovery: Local Account") == ["T1087.001"]
    assert parse_attack_ids(None) == []


def test_format_evidence_id_is_seed_mixed() -> None:
    # Updated from zero-padded ordinal: seed must change the id (P0-4).
    first = format_evidence_id(42, 0)
    second = format_evidence_id(42, 1)
    other_seed = format_evidence_id(99, 0)
    assert first.startswith("EVID-")
    assert len(first) == len("EVID-") + 8
    assert first != second
    assert first != other_seed
    assert format_evidence_id(42, 0) == first


@pytest.mark.skipif(not BRANCH_OFFICE_BUNDLE.is_dir(), reason="branch-office bundle not generated")
def test_build_canonical_events_branch_office_is_deterministic() -> None:
    scenario = _load_scenario(BRANCH_OFFICE_SCENARIO)
    first = build_canonical_events(BRANCH_OFFICE_BUNDLE, scenario, seed=42)
    second = build_canonical_events(BRANCH_OFFICE_BUNDLE, scenario, seed=42)
    assert canonical_events_digest(first) == canonical_events_digest(second)
    assert len(first) > 0
    assert first[0].evidence_id == format_evidence_id(42, 0)
    assert first[0].phase == "initial_access"


@pytest.mark.skipif(not RETAIL_BUNDLE.is_dir(), reason="retail bundle not generated")
def test_capture_different_seed_changes_digest() -> None:
    scenario = _load_scenario(RETAIL_SCENARIO)
    first = build_canonical_events(RETAIL_BUNDLE, scenario, seed=42)
    second = build_canonical_events(RETAIL_BUNDLE, scenario, seed=99)
    assert canonical_events_digest(first) != canonical_events_digest(second)
    assert first[0].evidence_id != second[0].evidence_id
    assert [event.ts for event in first] == [event.ts for event in second]


@pytest.mark.skipif(not BRANCH_OFFICE_BUNDLE.is_dir(), reason="branch-office bundle not generated")
def test_output_refs_resolve_known_branch_office_records() -> None:
    scenario = _load_scenario(BRANCH_OFFICE_SCENARIO)
    events = build_canonical_events(BRANCH_OFFICE_BUNDLE, scenario, seed=42)
    rdp_events = [event for event in events if event.kind == "rdp_session"]
    assert rdp_events, "expected at least one RDP canonical event"
    rdp = rdp_events[0]
    assert "zeek_conn" in rdp.output_refs
    assert "conn.json" in rdp.output_refs["zeek_conn"]

    process_events = [
        event
        for event in events
        if event.kind == "process" and "Compress-Archive" in str(event.fields)
    ]
    assert process_events, "expected staged archive process event"
    process = process_events[0]
    assert process.output_refs.get("windows_event_sysmon")


@pytest.mark.skipif(not RETAIL_BUNDLE.is_dir(), reason="retail bundle not generated")
def test_build_canonical_events_retail_storyline_count() -> None:
    scenario = _load_scenario(RETAIL_SCENARIO)
    events = build_canonical_events(RETAIL_BUNDLE, scenario, seed=42)
    assert len(events) == 22
    assert events[0].attack == ["T1190"]
    assert events[0].phase == "initial_access"


def test_write_canonical_events_roundtrip(tmp_path: Path) -> None:
    event_json = {
        "evidence_id": "EVID-000000",
        "ts": "2024-01-01T00:00:00Z",
        "phase": "initial_access",
        "attack": ["T1190"],
        "host": "HOST-01",
        "actor": "attacker",
        "kind": "connection",
        "fields": {"dst_port": 21},
        "observed_by": ["zeek_conn"],
        "output_refs": {"zeek_conn": "data/zeek/conn.json#L10"},
        "observation_status": "observed",
        "unresolved_sources": [],
        "record_id": "evt-001#0",
        "storyline_id": "evt-001",
    }
    from socbench.capture.models import CanonicalEvent

    events = [CanonicalEvent.model_validate(event_json)]
    out = tmp_path / "canonical_events.ndjson"
    write_canonical_events(events, out)
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["evidence_id"] == "EVID-000000"


def test_finalize_observation_symmetry() -> None:
    from socbench.capture.canonical_events import finalize_observation

    observed, unresolved, status = finalize_observation(
        ["zeek_conn", "ecar", "syslog"],
        {"zeek_conn": "data/zeek/conn.json#L2", "ecar": "data/host/ecar.json#L5"},
    )
    assert observed == ["ecar", "zeek_conn"]
    assert unresolved == ["syslog"]
    assert status == "partial"
    assert set(observed) == {"zeek_conn", "ecar"}


@pytest.mark.skipif(not BRANCH_OFFICE_BUNDLE.is_dir(), reason="branch-office bundle not generated")
@pytest.mark.skipif(not RETAIL_BUNDLE.is_dir(), reason="retail bundle not generated")
def test_observed_by_matches_output_refs_keys() -> None:
    for scenario_path, bundle in (
        (BRANCH_OFFICE_SCENARIO, BRANCH_OFFICE_BUNDLE),
        (RETAIL_SCENARIO, RETAIL_BUNDLE),
    ):
        scenario = _load_scenario(scenario_path)
        events = build_canonical_events(bundle, scenario, seed=42)
        for event in events:
            assert set(event.observed_by) == set(event.output_refs), event.record_id


@pytest.mark.skipif(not RETAIL_BUNDLE.is_dir(), reason="retail bundle not generated")
def test_unobservable_events_carry_explicit_marker() -> None:
    scenario = _load_scenario(RETAIL_SCENARIO)
    events = build_canonical_events(RETAIL_BUNDLE, scenario, seed=42)
    empty = [event for event in events if not event.observed_by]
    assert empty, "retail Linux process rows should include unobserved events"
    for event in empty:
        assert event.observation_status == "unobserved"
        assert isinstance(event.unresolved_sources, list)


@pytest.mark.skipif(not BRANCH_OFFICE_BUNDLE.is_dir(), reason="branch-office bundle not generated")
def test_multi_record_step_observed_by_per_record() -> None:
    """P0-1/P0-3: multi-record steps keep per-record observation after resolve.

    branch-office evt-003 has process + port_scan records; confirmed observed_by
    (and candidate sets via observed∪unresolved) must differ by kind.
    """
    scenario = _load_scenario(BRANCH_OFFICE_SCENARIO)
    events = build_canonical_events(BRANCH_OFFICE_BUNDLE, scenario, seed=42)
    step_events = [event for event in events if event.storyline_id == "evt-003"]
    assert len(step_events) >= 2
    by_kind = {
        event.kind: sorted(set(event.observed_by) | set(event.unresolved_sources))
        for event in step_events
    }
    assert "process" in by_kind
    assert "port_scan" in by_kind
    assert by_kind["process"] != by_kind["port_scan"]
    assert "windows_event_sysmon" in by_kind["process"] or "ecar" in by_kind["process"]
    assert "zeek_conn" in by_kind["port_scan"] or "cisco_asa" in by_kind["port_scan"]


def test_storyline_index_maps_techniques() -> None:
    scenario = _load_scenario(BRANCH_OFFICE_SCENARIO)
    index = build_storyline_index(scenario)
    assert index["evt-001"].attack


def test_resolve_output_refs_zeek_uid(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    sensor_dir = data_root / "ZEEK-BO-CORE"
    sensor_dir.mkdir(parents=True)
    conn_path = sensor_dir / "conn.json"
    # Matching uid on line 1 is valid when fields confirm the row (#L1 is OK then).
    conn_path.write_text(
        '{"uid":"TESTUID123","id.resp_h":"10.0.0.5","id.resp_p":443}\n',
        encoding="utf-8",
    )
    from socbench.capture.models import CanonicalEvent

    event = CanonicalEvent(
        evidence_id="EVID-000000",
        ts="2024-01-01T00:00:00Z",
        host="HOST-01",
        actor="attacker",
        kind="connection",
        fields={"uid": "TESTUID123"},
        record_id="evt-001#0",
    )
    refs = resolve_output_refs(event, data_root, ["zeek_conn"])
    assert refs["zeek_conn"].endswith("#L1")


def test_rglob_candidate_order_is_sorted(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    (data_root / "z-sensor").mkdir(parents=True)
    (data_root / "a-sensor").mkdir(parents=True)
    (data_root / "z-sensor" / "conn.json").write_text(
        '{"uid":"UID-Z","id.resp_h":"1.1.1.1","id.resp_p":1}\n',
        encoding="utf-8",
    )
    (data_root / "a-sensor" / "conn.json").write_text(
        '{"uid":"UID-A","id.resp_h":"2.2.2.2","id.resp_p":2}\n',
        encoding="utf-8",
    )
    from socbench.capture.output_refs import _candidate_files

    paths = _candidate_files(data_root, [], ("conn.json",))
    assert [path.parent.name for path in paths] == ["a-sensor", "z-sensor"]


def test_host_scoped_formats_skip_global_search_without_host_dir(tmp_path: Path) -> None:
    """Endpoint logs must not match unrelated hosts when the event host has no data/ dir."""
    data_root = tmp_path / "data"
    other_host = data_root / "OTHER-HOST.example"
    other_host.mkdir(parents=True)
    (other_host / "ecar.json").write_text('{"pid":246423,"command_line":"id"}\n', encoding="utf-8")
    (other_host / "windows_event_sysmon.xml").write_text(
        '<Event><EventData><Data Name="ProcessId">246423</Data></EventData></Event>',
        encoding="utf-8",
    )
    from socbench.capture.models import CanonicalEvent

    event = CanonicalEvent(
        evidence_id="EVID-000000",
        ts="2024-01-01T00:00:00Z",
        host="MUSIC-SRV-01",
        actor="attacker",
        kind="process",
        fields={"command_line": "id", "pid": 246423},
        record_id="evt-003#0",
    )
    refs = resolve_output_refs(
        event,
        data_root,
        ["ecar", "windows_event_sysmon", "windows_event_security"],
    )
    assert refs == {}


def test_no_line1_fallback_refs(tmp_path: Path) -> None:
    """Unrelated first lines must not become refs; only field-confirmed rows."""
    data_root = tmp_path / "data"
    host = data_root / "HOST-01.example"
    host.mkdir(parents=True)
    (host / "ecar.json").write_text(
        '{"cmd":"noise"}\n{"cmd":"other"}\n{"command_line":"whoami"}\n',
        encoding="utf-8",
    )
    asa_dir = data_root / "FW"
    asa_dir.mkdir()
    (asa_dir / "cisco_asa.log").write_text(
        "Built TCP for outside:9.9.9.9/80 to dmz:10.0.0.1/443\n"
        "Built TCP for outside:1.2.3.4/9999 to dmz:10.0.0.5/22\n",
        encoding="utf-8",
    )
    from socbench.capture.models import CanonicalEvent

    event = CanonicalEvent(
        evidence_id="EVID-000000",
        ts="2024-01-01T00:00:00Z",
        host="HOST-01",
        actor="attacker",
        kind="process",
        fields={"command_line": "whoami", "dst_ip": "1.2.3.4", "dst_port": 9999},
        record_id="evt-001#0",
    )
    refs = resolve_output_refs(event, data_root, ["ecar", "cisco_asa"])
    assert refs["ecar"].endswith("#L3")
    assert refs["cisco_asa"].endswith("#L2")
    assert not any(ref.endswith("#L1") for ref in refs.values())


def test_ground_truth_schema_drift_raises_clear_error(tmp_path: Path) -> None:
    from socbench.capture.canonical_events import build_canonical_events
    from socbench.capture.errors import SocbenchCaptureError

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "GROUND_TRUTH.json").write_text('{"schema_version": 1, "broken": true}\n', encoding="utf-8")
    scenario = _load_scenario(BRANCH_OFFICE_SCENARIO)
    with pytest.raises(SocbenchCaptureError) as exc_info:
        build_canonical_events(bundle, scenario, seed=42)
    assert "Invalid GROUND_TRUTH.json schema" in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, Exception)
