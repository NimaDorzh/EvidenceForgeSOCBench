"""Tests for Panda truth projection (per-stage BLUF containment)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from evidenceforge.models.scenario import Scenario
from socbench.capture.canonical_events import build_canonical_events
from socbench.capture.models import CanonicalEvent
from socbench.stage.world_state import StaticWorldState, world_state_from_events
from socbench.truth.panda import build_panda_manifest
from tests.socbench.colonial_fixtures import (
    COLONIAL_FULL_BUNDLE,
    COLONIAL_SCENARIO,
    COLONIAL_WINDOW_START,
    REQUIRES_COLONIAL_FULL_DATA,
)


def _event(
    *,
    evidence_id: str,
    ts: str,
    host: str,
    kind: str = "process",
    fields: dict | None = None,
) -> CanonicalEvent:
    return CanonicalEvent(
        evidence_id=evidence_id,
        ts=ts,
        host=host,
        actor="attacker",
        kind=kind,
        attack=[],
        fields=fields or {},
        record_id=f"{evidence_id}#0",
    )


def test_panda_stage_zero_is_monitor_not_isolate() -> None:
    events = [
        _event(
            evidence_id="EVID-vpn",
            ts="2024-06-03T08:05:00Z",
            host="VPN-GW-01",
            kind="connection",
            fields={"source_ip": "198.18.50.33", "dst_ip": "10.60.10.10"},
        ),
        _event(
            evidence_id="EVID-rdp",
            ts="2024-06-03T08:20:00Z",
            host="WKS-OPS-01",
            kind="rdp_session",
            fields={"source_ip": "10.60.10.10"},
        ),
    ]
    state = world_state_from_events(events, window_start=COLONIAL_WINDOW_START)
    manifest = build_panda_manifest(state, window_start=COLONIAL_WINDOW_START)
    stage0 = manifest["stages"][0]
    assert stage0["incident_phase"] == "initial_access"
    assert stage0["premature_containment_trap"] is True
    kinds = {action["kind"] for action in stage0["recommended_actions"]}
    assert "no_action" in kinds
    assert "isolate_host" not in kinds


def test_panda_lateral_stage_recommends_isolation_and_smb_block() -> None:
    events = [
        _event(
            evidence_id="EVID-psexec",
            ts="2024-06-03T08:46:00Z",
            host="WKS-OPS-01",
            fields={"command_line": "PsExec.exe \\\\FS-01 -accepteula -s cmd.exe"},
        ),
        _event(
            evidence_id="EVID-svc",
            ts="2024-06-03T08:47:00Z",
            host="FS-01",
            kind="service_installed",
            fields={"service_name": "PSEXESVC"},
        ),
    ]
    state = world_state_from_events(events, window_start=COLONIAL_WINDOW_START)
    manifest = build_panda_manifest(state, window_start=COLONIAL_WINDOW_START)
    stage = manifest["stages"][-1]
    assert stage["incident_phase"] == "lateral_movement"
    kinds = {action["kind"] for action in stage["recommended_actions"]}
    assert "isolate_host" in kinds
    assert "block_smb" in kinds


def test_panda_exfil_stage_blocks_egress() -> None:
    events = [
        _event(
            evidence_id="EVID-exfil",
            ts="2024-06-03T09:36:00Z",
            host="FTP-01",
            kind="connection",
            fields={"dst_ip": "203.0.113.88", "dst_port": 21, "orig_bytes": 1000},
        ),
    ]
    state = world_state_from_events(events, window_start=COLONIAL_WINDOW_START)
    manifest = build_panda_manifest(state, window_start=COLONIAL_WINDOW_START)
    stage = manifest["stages"][-1]
    assert stage["incident_phase"] == "exfiltration"
    assert any(action["kind"] == "block_egress" for action in stage["recommended_actions"])


def test_panda_uses_world_state_slice_not_future_events() -> None:
    events = [
        _event(
            evidence_id="EVID-early",
            ts="2024-06-03T08:05:00Z",
            host="VPN-GW-01",
            kind="connection",
            fields={"source_ip": "198.18.50.33", "dst_ip": "10.60.10.10"},
        ),
        _event(
            evidence_id="EVID-late",
            ts="2024-06-03T09:36:00Z",
            host="FTP-01",
            kind="connection",
            fields={"dst_ip": "203.0.113.88", "dst_port": 21, "orig_bytes": 1000},
        ),
    ]
    state = StaticWorldState.from_events(events, window_start=COLONIAL_WINDOW_START)
    stage0_manifest = build_panda_manifest(
        state,
        window_start=COLONIAL_WINDOW_START,
    )
    assert stage0_manifest["stages"][0]["incident_phase"] == "initial_access"
    assert "EVID-late" not in stage0_manifest["stages"][0]["supporting_evidence_ids"]


@REQUIRES_COLONIAL_FULL_DATA
def test_panda_ignores_ground_truth_labels() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_FULL_BUNDLE, scenario, seed=42)
    baseline_state = world_state_from_events(events, window_start=COLONIAL_WINDOW_START)
    baseline = build_panda_manifest(baseline_state, window_start=COLONIAL_WINDOW_START)

    stripped = [
        event.model_copy(update={"phase": None, "attack": [], "actor": ""}) for event in events
    ]
    redacted_state = world_state_from_events(stripped, window_start=COLONIAL_WINDOW_START)
    redacted = build_panda_manifest(redacted_state, window_start=COLONIAL_WINDOW_START)

    assert redacted["stages"] == baseline["stages"]


@REQUIRES_COLONIAL_FULL_DATA
def test_colonial_panda_stage_phases_progress() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_FULL_BUNDLE, scenario, seed=42)
    state = world_state_from_events(events, window_start=COLONIAL_WINDOW_START)
    manifest = build_panda_manifest(state, window_start=COLONIAL_WINDOW_START)
    phases = [stage["incident_phase"] for stage in manifest["stages"]]
    assert phases[0] == "initial_access"
    assert "lateral_movement" in phases
    assert phases[-1] == "impact"
