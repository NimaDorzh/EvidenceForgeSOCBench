"""Panda task truth projector (per-stage BLUF containment ground truth)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from evidenceforge.utils.paths import safe_write_text
from socbench.capture.models import CanonicalEvent
from socbench.stage.world_state import StaticWorldState, WorldState, world_state_from_events
from socbench.truth.common import (
    DEFAULT_STAGE_MINUTES,
    is_exfil_connection_event,
    is_initial_access_event,
    is_psexec_helper_service,
    is_psexec_launcher_event,
    is_ransomware_event,
    is_staging_event,
    is_vss_delete_event,
    load_canonical_events,
    normalize_hostname,
    parse_ts,
    protocol_label,
    psexec_target_hosts,
    stage_end_ts,
    stage_of,
)

PANDA_MANIFEST_FILENAME = "panda.json"

IncidentPhase = Literal[
    "initial_access",
    "lateral_movement",
    "staging",
    "exfiltration",
    "impact",
]

ActionKind = Literal[
    "no_action",
    "monitor",
    "isolate_host",
    "block_smb",
    "block_egress",
    "segment_change",
    "disable_account",
]


def build_panda_manifest(
    world_state: WorldState,
    *,
    window_start: str | datetime | None = None,
    stage_minutes: int = DEFAULT_STAGE_MINUTES,
) -> dict[str, Any]:
    """Build per-stage BLUF containment ground truth from a world-state slice."""
    if not isinstance(world_state, StaticWorldState):
        msg = "Panda manifest build requires StaticWorldState in v1"
        raise TypeError(msg)

    events = world_state.events
    if not events:
        return _empty_manifest(stage_minutes=stage_minutes)

    if window_start is None:
        origin = world_state.window_start
    elif isinstance(window_start, str):
        origin = parse_ts(window_start)
    else:
        origin = window_start.astimezone(UTC)
    max_stage = max(stage_of(event.ts, origin, stage_minutes=stage_minutes) for event in events)

    stages: list[dict[str, Any]] = []
    for stage in range(max_stage + 1):
        cumulative = world_state.slice_through(stage)
        phase = _classify_incident_phase(cumulative)
        action_targets = _action_targets(cumulative, phase=phase)
        recommended_actions = _recommended_actions(phase, action_targets)
        stages.append(
            {
                "stage": stage,
                "stage_end": stage_end_ts(origin, stage, stage_minutes=stage_minutes),
                "incident_phase": phase,
                "bluf": _bluf_text(phase, action_targets),
                "recommended_actions": recommended_actions,
                "action_targets": action_targets,
                "premature_containment_trap": _premature_containment_trap(phase),
                "supporting_evidence_ids": _supporting_evidence_ids(cumulative, phase),
            }
        )

    return {
        "task": "panda",
        "schema_version": 1,
        "window_start": origin.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stage_minutes": stage_minutes,
        "stages": stages,
        "assumptions": {
            "source": "WorldState.slice_through(stage) — static mode uses full canonical timeline",
            "observation_status": "Phase detection uses observable kind/fields only (DP2-safe)",
            "premature_containment_trap": (
                "Grader penalizes aggressive isolation/blocking before lateral or exfil evidence"
            ),
        },
    }


def build_panda_manifest_from_file(
    events_path: Path,
    *,
    world_state: WorldState | None = None,
    window_start: str | None = None,
    stage_minutes: int = DEFAULT_STAGE_MINUTES,
) -> dict[str, Any]:
    """Load canonical events and build Panda manifest via WorldState."""
    events = load_canonical_events(events_path)
    state = world_state or world_state_from_events(
        events,
        window_start=window_start,
        stage_minutes=stage_minutes,
    )
    return build_panda_manifest(
        state,
        window_start=window_start,
        stage_minutes=stage_minutes,
    )


def write_panda_manifest(manifest: dict[str, Any], path: Path) -> Path:
    """Write Panda manifest JSON to disk."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    safe_write_text(path, json.dumps(manifest, indent=2, sort_keys=False) + "\n")
    return path


def _classify_incident_phase(events: list[CanonicalEvent]) -> IncidentPhase:
    if any(is_ransomware_event(event) for event in events):
        return "impact"
    if any(is_exfil_connection_event(event) for event in events):
        return "exfiltration"
    if any(_is_staging_process(event) or is_vss_delete_event(event) for event in events):
        return "staging"
    if _has_lateral_movement(events):
        return "lateral_movement"
    return "initial_access"


def _has_lateral_movement(events: list[CanonicalEvent]) -> bool:
    for event in events:
        if is_psexec_launcher_event(event) or is_psexec_helper_service(event):
            return True
        if event.kind == "logon" and str(event.fields.get("logon_type")) == "3":
            source_ip = event.fields.get("source_ip")
            if isinstance(source_ip, str) and source_ip.startswith("10."):
                return True
        if event.kind == "explicit_credentials":
            return True
    return False


def _is_staging_process(event: CanonicalEvent) -> bool:
    if event.kind != "process":
        return False
    command_line = str(event.fields.get("command_line", "")).lower()
    return (
        is_staging_event(event)
        and (
            "compress-archive" in command_line
            or "uploadfile(" in command_line
            or "xcopy" in command_line
        )
    )


def _compromised_hosts(events: list[CanonicalEvent]) -> set[str]:
    hosts: set[str] = set()
    for event in events:
        if event.kind in {"connection", "ssh_session", "rdp_session"} and is_initial_access_event(
            event
        ):
            hosts.add(normalize_hostname(event.host))
            continue
        if is_psexec_launcher_event(event):
            hosts.add(normalize_hostname(event.host))
            hosts.update(psexec_target_hosts(event))
        if is_psexec_helper_service(event):
            hosts.add(normalize_hostname(event.host))
        if event.kind in {"logon", "explicit_credentials", "process", "service_installed"}:
            if _is_attacker_process(event) or event.kind != "process":
                hosts.add(normalize_hostname(event.host))
        if is_staging_event(event) or is_exfil_connection_event(event) or is_ransomware_event(
            event
        ):
            hosts.add(normalize_hostname(event.host))
    return {host for host in hosts if host}


def _is_attacker_process(event: CanonicalEvent) -> bool:
    command_line = str(event.fields.get("command_line", "")).lower()
    process_name = str(event.fields.get("process_name", "")).lower()
    markers = (
        "procdump",
        "psexec",
        "compress-archive",
        "uploadfile(",
        "xcopy",
        "darkside",
        "vssadmin",
        "nltest",
        "net view",
    )
    return any(marker in command_line or marker in process_name for marker in markers)


def _lateral_targets(events: list[CanonicalEvent]) -> set[str]:
    targets: set[str] = set()
    for event in events:
        if is_psexec_launcher_event(event):
            targets.update(psexec_target_hosts(event))
        if is_psexec_helper_service(event):
            targets.add(normalize_hostname(event.host))
        if event.kind == "logon" and str(event.fields.get("logon_type")) == "3":
            targets.add(normalize_hostname(event.host))
    return {host for host in targets if host}


def _exfil_protocols(events: list[CanonicalEvent]) -> list[str]:
    protocols = {
        protocol_label(event)
        for event in events
        if is_exfil_connection_event(event)
    }
    return sorted(protocol for protocol in protocols if protocol != "unknown")


def _action_targets(
    events: list[CanonicalEvent],
    *,
    phase: IncidentPhase,
) -> dict[str, Any]:
    compromised = sorted(_compromised_hosts(events))
    lateral = sorted(_lateral_targets(events))
    exfil_hosts = sorted(
        {
            normalize_hostname(event.host)
            for event in events
            if is_exfil_connection_event(event)
        }
    )
    staging_hosts = sorted(
        {
            normalize_hostname(event.host)
            for event in events
            if _is_staging_process(event)
        }
    )
    file_servers = sorted({host for host in lateral + staging_hosts + exfil_hosts if host})

    targets: dict[str, Any] = {
        "hosts": compromised,
        "file_servers": file_servers,
        "lateral_targets": lateral,
        "exfil_hosts": exfil_hosts,
        "protocols": _exfil_protocols(events),
    }
    if phase == "initial_access":
        entry_hosts = sorted(
            {
                normalize_hostname(event.host)
                for event in events
                if is_initial_access_event(event)
            }
        )
        targets["entry_hosts"] = entry_hosts
    return targets


def _recommended_actions(
    phase: IncidentPhase,
    action_targets: dict[str, Any],
) -> list[dict[str, Any]]:
    entry_hosts = action_targets.get("entry_hosts", [])
    compromised = action_targets.get("hosts", [])
    file_servers = action_targets.get("file_servers", [])
    lateral_targets = action_targets.get("lateral_targets", [])
    exfil_hosts = action_targets.get("exfil_hosts", [])
    protocols = action_targets.get("protocols", [])

    if phase == "initial_access":
        return [
            {"kind": "no_action", "targets": [], "rationale": "Insufficient spread evidence"},
            {
                "kind": "monitor",
                "targets": entry_hosts or compromised,
                "rationale": "Track pivot activity before containment",
            },
        ]

    if phase == "lateral_movement":
        pivot_hosts = sorted(
            {
                host
                for host in compromised
                if host.startswith("WKS-") or host.startswith("VPN-")
            }
        )
        actions: list[dict[str, Any]] = []
        if pivot_hosts:
            actions.append(
                {
                    "kind": "isolate_host",
                    "targets": pivot_hosts,
                    "rationale": "Stop active pivot workstation",
                }
            )
        if lateral_targets or file_servers:
            actions.append(
                {
                    "kind": "block_smb",
                    "targets": sorted(set(lateral_targets) | set(file_servers)),
                    "rationale": "Contain lateral SMB/remote-exec spread",
                }
            )
        if file_servers:
            actions.append(
                {
                    "kind": "segment_change",
                    "targets": file_servers,
                    "rationale": "Segment newly touched file servers",
                }
            )
        return actions

    if phase == "staging":
        actions = []
        if file_servers:
            actions.append(
                {
                    "kind": "isolate_host",
                    "targets": file_servers,
                    "rationale": "Staging activity on file servers",
                }
            )
        actions.append(
            {
                "kind": "monitor",
                "targets": sorted(set(compromised) - set(file_servers)),
                "rationale": "Watch for outbound transfer setup",
            }
        )
        return actions

    if phase == "exfiltration":
        return [
            {
                "kind": "block_egress",
                "targets": exfil_hosts or file_servers,
                "protocols": protocols or ["ftp", "https"],
                "rationale": "Stop active outbound data theft",
            },
            {
                "kind": "isolate_host",
                "targets": sorted(set(file_servers) | set(exfil_hosts)),
                "rationale": "Quarantine staging/exfil hosts",
            },
        ]

    return [
        {
            "kind": "isolate_host",
            "targets": file_servers or compromised,
            "rationale": "Encryption impact — full host isolation",
        },
        {
            "kind": "block_egress",
            "targets": exfil_hosts or file_servers,
            "protocols": protocols or ["ftp", "https"],
            "rationale": "Prevent further exfil during impact",
        },
        {
            "kind": "disable_account",
            "targets": [],
            "rationale": "Disable privileged accounts used in lateral movement",
        },
    ]


def _bluf_text(phase: IncidentPhase, action_targets: dict[str, Any]) -> str:
    hosts = ", ".join(action_targets.get("hosts", [])[:4]) or "internal hosts"
    if phase == "initial_access":
        return (
            f"External initial access observed ({hosts}); continue monitoring — "
            "premature enterprise isolation not yet warranted."
        )
    if phase == "lateral_movement":
        lateral = ", ".join(action_targets.get("lateral_targets", [])[:3]) or "file servers"
        return (
            f"Active lateral movement toward {lateral}; isolate pivot hosts and "
            "block SMB/admin paths to file servers."
        )
    if phase == "staging":
        staging = ", ".join(action_targets.get("file_servers", [])[:3]) or hosts
        return f"Collection/staging on {staging}; isolate affected servers and prepare egress blocks."
    if phase == "exfiltration":
        protocols = ", ".join(action_targets.get("protocols", [])) or "outbound transfers"
        return f"Active exfiltration via {protocols}; block egress and isolate staging/exfil hosts."
    return f"Encryption impact on {hosts}; execute full containment and account lockdown."


def _premature_containment_trap(phase: IncidentPhase) -> bool:
    return phase == "initial_access"


def _supporting_evidence_ids(
    events: list[CanonicalEvent],
    phase: IncidentPhase,
) -> list[str]:
    ids: list[str] = []
    for event in events:
        if phase == "initial_access" and is_initial_access_event(event):
            ids.append(event.evidence_id)
        elif phase == "lateral_movement" and (
            is_psexec_launcher_event(event)
            or is_psexec_helper_service(event)
            or event.kind in {"logon", "explicit_credentials"}
        ):
            ids.append(event.evidence_id)
        elif phase == "staging" and (_is_staging_process(event) or is_vss_delete_event(event)):
            ids.append(event.evidence_id)
        elif phase == "exfiltration" and is_exfil_connection_event(event):
            ids.append(event.evidence_id)
        elif phase == "impact" and is_ransomware_event(event):
            ids.append(event.evidence_id)
    return ids


def _empty_manifest(*, stage_minutes: int) -> dict[str, Any]:
    return {
        "task": "panda",
        "schema_version": 1,
        "window_start": None,
        "stage_minutes": stage_minutes,
        "stages": [],
        "assumptions": {},
    }
