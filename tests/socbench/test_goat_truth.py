"""Tests for Goat ransomware-impact truth projection."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from evidenceforge.models.scenario import Scenario
from socbench.capture.canonical_events import build_canonical_events
from socbench.capture.models import CanonicalEvent
from socbench.truth.common import (
    extract_encrypt_paths,
    is_vss_delete_event,
    parse_share_path,
)
from socbench.truth.goat import (
    GOAT_BYTE_TOLERANCE_FRACTION,
    GOAT_DIR_FRACTION_TOLERANCE,
    GOAT_TIME_TOLERANCE_MINUTES,
    build_goat_manifest,
)
from tests.socbench.colonial_fixtures import (
    COLONIAL_FULL_BUNDLE,
    COLONIAL_SCENARIO,
    COLONIAL_WINDOW_START,
    REQUIRES_COLONIAL_FULL_DATA,
)


def test_extract_encrypt_paths_from_command_line() -> None:
    event = CanonicalEvent(
        evidence_id="EVID-r",
        ts="2024-01-01T01:00:00Z",
        host="FS-01",
        actor="attacker",
        kind="process",
        fields={
            "command_line": (
                r"C:\ProgramData\darkside_svc.exe --encrypt \\FS-01\Finance "
                r"\\FS-01\Engineering --key-id 0x733100"
            )
        },
        record_id="evt-009a#0",
    )
    paths = extract_encrypt_paths(event)
    assert paths == [r"\\FS-01\Finance", r"\\FS-01\Engineering"]


def test_extract_encrypt_paths_from_overescaped_gt_command_line() -> None:
    event = CanonicalEvent(
        evidence_id="EVID-r-colonial",
        ts="2024-06-03T10:06:39Z",
        host="FS-01",
        actor="attacker",
        kind="process",
        fields={
            "command_line": (
                "C:\\\\ProgramData\\\\darkside_svc.exe --encrypt "
                "\\\\\\\\FS-01\\\\Finance \\\\\\\\FS-01\\\\HR --key-id 0x733100"
            ),
            "process_name": "C:\\ProgramData\\darkside_svc.exe",
        },
        record_id="evt-009a#0",
    )
    paths = extract_encrypt_paths(event)
    assert paths == [r"\\FS-01\Finance", r"\\FS-01\HR"]


def test_parse_share_path() -> None:
    host, share, full_path = parse_share_path(r"\\FS-02\Contracts")
    assert host == "FS-02"
    assert share == "Contracts"
    assert full_path == r"\\FS-02\Contracts"


def test_is_vss_delete_event() -> None:
    event = CanonicalEvent(
        evidence_id="EVID-vss",
        ts="2024-01-01T00:30:00Z",
        host="FS-01",
        actor="attacker",
        kind="process",
        fields={
            "process_name": r"C:\Windows\System32\vssadmin.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
        },
        record_id="evt-008#0",
    )
    assert is_vss_delete_event(event) is True


def test_build_goat_manifest_stage_progression() -> None:
    events = [
        CanonicalEvent(
            evidence_id="EVID-vss",
            ts="2024-06-03T09:59:39Z",
            host="FS-01",
            actor="attacker",
            kind="process",
            fields={
                "process_name": r"C:\Windows\System32\vssadmin.exe",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
            },
            record_id="evt-008#0",
        ),
        CanonicalEvent(
            evidence_id="EVID-r1",
            ts="2024-06-03T10:06:39Z",
            host="FS-01",
            actor="attacker",
            kind="process",
            fields={
                "pid": 6001,
                "process_name": r"C:\ProgramData\darkside_svc.exe",
                "command_line": (
                    r"C:\ProgramData\darkside_svc.exe --encrypt \\FS-01\Finance "
                    r"\\FS-01\HR --key-id 0x733100"
                ),
            },
            record_id="evt-009a#0",
        ),
        CanonicalEvent(
            evidence_id="EVID-r2",
            ts="2024-06-03T10:11:39Z",
            host="FS-02",
            actor="attacker",
            kind="process",
            fields={
                "pid": 6002,
                "process_name": r"C:\ProgramData\darkside_svc.exe",
                "command_line": (
                    r"C:\ProgramData\darkside_svc.exe --encrypt \\FS-02\Operations "
                    r"--key-id 0x733100"
                ),
            },
            record_id="evt-009b#0",
        ),
    ]
    manifest = build_goat_manifest(events, window_start=COLONIAL_WINDOW_START, stage_minutes=30)
    by_stage = {entry["stage"]: entry for entry in manifest["stages"]}

    assert len(manifest["o3_vss_events"]) == 1
    assert manifest["o3_vss_events"][0]["event_type"] == "delete_shadows"
    assert len(manifest["o4_attribution"]) == 2

    stage3 = by_stage[3]
    statuses = {row["path"]: row["status"] for row in stage3["o1_encrypted_paths"]}
    assert statuses[r"\\FS-01\Finance"] == "not_yet_encrypted"
    assert statuses[r"\\FS-02\Operations"] == "not_yet_encrypted"

    stage4 = by_stage[4]
    statuses4 = {row["path"]: row["status"] for row in stage4["o1_encrypted_paths"]}
    assert statuses4[r"\\FS-01\Finance"] == "encrypted"
    assert statuses4[r"\\FS-02\Operations"] == "encrypted"

    final_stage = manifest["stages"][-1]
    assert all(row["status"] == "encrypted" for row in final_stage["o1_encrypted_paths"])
    assert manifest["manifest_thresholds"]["byte_tolerance_fraction"] == GOAT_BYTE_TOLERANCE_FRACTION
    assert manifest["manifest_thresholds"]["time_tolerance_minutes"] == GOAT_TIME_TOLERANCE_MINUTES
    assert manifest["manifest_thresholds"]["dir_fraction_tolerance"] == GOAT_DIR_FRACTION_TOLERANCE


@REQUIRES_COLONIAL_FULL_DATA
def test_colonial_goat_manifest() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_FULL_BUNDLE, scenario, seed=42)
    manifest = build_goat_manifest(events, window_start=COLONIAL_WINDOW_START, stage_minutes=30)

    assert manifest["task"] == "goat"
    assert len(manifest["o3_vss_events"]) == 1
    assert manifest["o3_vss_events"][0]["host"] == "FS-01"
    assert len(manifest["o4_attribution"]) == 2

    final_paths = manifest["stages"][-1]["o1_encrypted_paths"]
    encrypted_paths = {row["path"] for row in final_paths if row["status"] == "encrypted"}
    assert r"\\FS-01\Finance" in encrypted_paths
    assert r"\\FS-02\Operations" in encrypted_paths

    fs01_impact = [
        row
        for row in manifest["stages"][-1]["o2_impact_by_host_share"]
        if row["host"] == "FS-01" and row["share"] == "Finance"
    ]
    assert fs01_impact
    assert fs01_impact[0]["encrypted_fraction"] == 1.0


@REQUIRES_COLONIAL_FULL_DATA
def test_goat_ignores_ground_truth_labels() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_FULL_BUNDLE, scenario, seed=42)
    baseline = build_goat_manifest(events, window_start=COLONIAL_WINDOW_START, stage_minutes=30)

    stripped = [
        event.model_copy(update={"phase": None, "attack": [], "actor": ""}) for event in events
    ]
    redacted = build_goat_manifest(
        stripped,
        window_start=COLONIAL_WINDOW_START,
        stage_minutes=30,
    )

    assert redacted["stages"] == baseline["stages"]
    assert redacted["o3_vss_events"] == baseline["o3_vss_events"]
    assert redacted["o4_attribution"] == baseline["o4_attribution"]
