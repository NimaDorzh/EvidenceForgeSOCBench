"""Tests for Mouse exfiltration truth projection."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from evidenceforge.models.scenario import Scenario
from socbench.capture.canonical_events import build_canonical_events
from socbench.truth.mouse import (
    MOUSE_INVOLVED_HOSTS_TOLERANCE,
    MOUSE_START_TIME_TOLERANCE_MINUTES,
    MOUSE_VOLUME_TOLERANCE_GB,
    build_mouse_manifest,
)
from tests.socbench.colonial_fixtures import (
    COLONIAL_FULL_BUNDLE,
    COLONIAL_SCENARIO,
    REQUIRES_COLONIAL_FULL_DATA,
)


@REQUIRES_COLONIAL_FULL_DATA
def test_colonial_mouse_exfil_manifest() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_FULL_BUNDLE, scenario, seed=42)
    manifest = build_mouse_manifest(events)

    assert manifest["exfil_happens"] is True
    assert manifest["o1_exfil_occurred"] == "Yes"
    assert manifest["o2_start_time"] == "2024-06-03T09:36:18Z"
    assert manifest["o3_volume_gb"] > 0
    assert set(manifest["o4_involved_hosts"]) == {"FS-01", "FTP-01"}
    assert manifest["o5_protocols"]["primary"] == "ftp"
    channels = {entry["protocol"]: entry["bytes"] for entry in manifest["o5_protocols"]["channels"]}
    assert channels["ftp"] > channels["https"]
    assert "EVID-5cbc8381" in manifest["evidence_ids"]["exfiltration"]
    assert manifest["tolerances"]["start_time_minutes"] == MOUSE_START_TIME_TOLERANCE_MINUTES
    assert manifest["tolerances"]["volume_gb"] == MOUSE_VOLUME_TOLERANCE_GB
    assert manifest["tolerances"]["involved_hosts"] == MOUSE_INVOLVED_HOSTS_TOLERANCE


def test_mouse_no_exfil_branch() -> None:
    from socbench.capture.models import CanonicalEvent

    events = [
        CanonicalEvent(
            evidence_id="EVID-local",
            ts="2024-01-01T00:00:00Z",
            host="HOST-01",
            actor="user",
            kind="connection",
            fields={"dst_ip": "10.0.0.5", "dst_port": 443},
            record_id="evt-001#0",
        )
    ]
    manifest = build_mouse_manifest(events)
    assert manifest["exfil_happens"] is False
    assert manifest["o1_exfil_occurred"] == "No"
    assert manifest["o2_start_time"] is None


def test_mouse_uses_gt_fields_regardless_of_observation_status() -> None:
    from socbench.capture.models import CanonicalEvent

    observed = CanonicalEvent(
        evidence_id="EVID-observed",
        ts="2024-06-03T09:36:18Z",
        host="FTP-01",
        actor="attacker",
        kind="connection",
        fields={
            "dst_ip": "203.0.113.88",
            "dst_port": 21,
            "orig_bytes": 500_000_000,
            "service": "ftp",
        },
        observation_status="observed",
        record_id="EVID-observed#0",
    )
    partial = CanonicalEvent(
        evidence_id="EVID-partial",
        ts="2024-06-03T09:36:21Z",
        host="FTP-01",
        actor="attacker",
        kind="connection",
        fields={
            "dst_ip": "203.0.113.90",
            "dst_port": 443,
            "orig_bytes": 250_000_000,
            "service": "ssl",
        },
        observation_status="partial",
        unresolved_sources=["ecar"],
        record_id="EVID-partial#0",
    )

    manifest = build_mouse_manifest([observed, partial])
    channels = {entry["protocol"]: entry["bytes"] for entry in manifest["o5_protocols"]["channels"]}

    assert manifest["o2_start_time"] == "2024-06-03T09:36:18Z"
    assert channels["ftp"] == 500_000_000
    assert channels["https"] == 250_000_000
    assert manifest["o5_protocols"]["primary"] == "ftp"
    assert manifest["o3_volume_gb"] == round((750_000_000) / (1024**3), 3)
    assert set(manifest["evidence_ids"]["exfiltration"]) == {"EVID-observed", "EVID-partial"}


@REQUIRES_COLONIAL_FULL_DATA
def test_mouse_ignores_ground_truth_labels() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_FULL_BUNDLE, scenario, seed=42)
    baseline = build_mouse_manifest(events)

    stripped = [
        event.model_copy(update={"phase": None, "attack": [], "actor": ""}) for event in events
    ]
    redacted = build_mouse_manifest(stripped)

    for key in (
        "o1_exfil_occurred",
        "o2_start_time",
        "o3_volume_gb",
        "o4_involved_hosts",
        "o5_protocols",
    ):
        assert redacted[key] == baseline[key]
