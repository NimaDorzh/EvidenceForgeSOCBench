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


def test_format_evidence_id_is_zero_padded() -> None:
    assert format_evidence_id(42, 0) == "EVID-000000"
    assert format_evidence_id(42, 123) == "EVID-000123"


@pytest.mark.skipif(not BRANCH_OFFICE_BUNDLE.is_dir(), reason="branch-office bundle not generated")
def test_build_canonical_events_branch_office_is_deterministic() -> None:
    scenario = _load_scenario(BRANCH_OFFICE_SCENARIO)
    first = build_canonical_events(BRANCH_OFFICE_BUNDLE, scenario, seed=42)
    second = build_canonical_events(BRANCH_OFFICE_BUNDLE, scenario, seed=42)
    assert canonical_events_digest(first) == canonical_events_digest(second)
    assert len(first) > 0
    assert first[0].evidence_id == "EVID-000000"
    assert first[0].phase == "initial_access"


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
        "output_refs": {},
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


def test_no_line1_fallback_refs(tmp_path: Path) -> None:
    """Unrelated first lines must not become refs; only field-confirmed rows."""
    data_root = tmp_path / "data"
    host = data_root / "HOST-01.example"
    host.mkdir(parents=True)
    # Line 1 is noise; matching command_line is on line 3.
    (host / "ecar.json").write_text(
        '{"cmd":"noise"}\n{"cmd":"other"}\n{"command_line":"whoami"}\n',
        encoding="utf-8",
    )
    # ASA line 1 has a different IP/port; true match is later.
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


@pytest.mark.skipif(not BRANCH_OFFICE_BUNDLE.is_dir(), reason="branch-office bundle not generated")
def test_multi_record_step_observed_by_per_record() -> None:
    """P0-1: multi-record storyline steps must not share one storyline-wide observed_by.

    branch-office evt-003 has process records and a port_scan record; candidates
    (and final observed_by after later P0-3) must differ by record kind.
    """
    scenario = _load_scenario(BRANCH_OFFICE_SCENARIO)
    events = build_canonical_events(BRANCH_OFFICE_BUNDLE, scenario, seed=42)
    step_events = [event for event in events if event.storyline_id == "evt-003"]
    assert len(step_events) >= 2
    by_kind = {event.kind: event.observed_by for event in step_events}
    assert "process" in by_kind
    assert "port_scan" in by_kind
    # Process candidates are endpoint-oriented; port_scan candidates are network-oriented.
    assert by_kind["process"] != by_kind["port_scan"]
    assert "windows_event_sysmon" in by_kind["process"] or "ecar" in by_kind["process"]
    assert "zeek_conn" in by_kind["port_scan"] or "cisco_asa" in by_kind["port_scan"]
