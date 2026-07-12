"""Dataset consistency validation for SOC-bench exports."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from socbench.capture.models import CanonicalEvent
from socbench.export_agent import find_dp2_violations
from socbench.stage.bucketize import linked_evidence_stage_indices
from socbench.truth.common import (
    DEFAULT_STAGE_MINUTES,
    index_by_evidence_id,
    load_canonical_events,
    parse_ts,
    resolve_evidence_id,
    resolve_window_start,
    stage_of,
)

EVIDENCE_ID_PATTERN = re.compile(r"^EVID-[0-9a-f]+$")
HELPDESK_TICKET_PATTERN = re.compile(r"^HD-")

SIEM_RULE_KIND: dict[str, str] = {
    "CORR-001": "service_installed",
    "CORR-002": "process",
    "CORR-003": "connection",
    "CORR-004": "process",
    "CORR-005": "process",
    "CORR-006": "create_remote_thread",
    "CORR-007": "rdp_session",
}

KIND_TO_SIEM_RULES: dict[str, tuple[str, ...]] = {
    "service_installed": ("CORR-001",),
    "connection": ("CORR-003",),
    "create_remote_thread": ("CORR-006",),
    "rdp_session": ("CORR-007",),
    "process": ("CORR-002", "CORR-004", "CORR-005"),
}

_EVIDENCE_ID_KEYS = frozenset(
    {
        "evidence_id",
        "evidence_ids",
        "supporting_evidence_ids",
        "forbidden_evidence_ids",
        "first_affected_evidence_id",
        "first_ransomware_evidence_id",
    }
)


@dataclass
class ValidationResult:
    """Aggregate validation outcome."""

    dataset_root: Path
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def validate_dataset(dataset_root: Path) -> ValidationResult:
    """Run all dataset consistency checks and return aggregated errors."""
    dataset_root = dataset_root.resolve()
    result = ValidationResult(dataset_root=dataset_root)

    for check in (
        validate_claim_evidence_ids_resolve,
        validate_helpdesk_not_positive_evidence,
        validate_dp2_agent_clean,
        validate_causality_respects_stage_order,
        validate_tiger_verifiable_edges_reconstructible,
    ):
        result.errors.extend(check(dataset_root))

    return result


def validate_claim_evidence_ids_resolve(dataset_root: Path) -> list[str]:
    """Ensure every manifest evidence_id resolves to a canonical event."""
    events_path = dataset_root / "grader" / "canonical_events.ndjson"
    manifests_dir = dataset_root / "grader" / "manifests"
    if not events_path.is_file():
        return [f"missing canonical events: {events_path}"]

    events = load_canonical_events(events_path)
    events_by_id = index_by_evidence_id(events)
    errors: list[str] = []

    for manifest_path in sorted(manifests_dir.glob("*.json")):
        if manifest_path.name.endswith("_ged_spec.json"):
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for evidence_id in sorted(_collect_manifest_evidence_ids(manifest)):
            try:
                resolve_evidence_id(evidence_id, events_by_id)
            except Exception:
                errors.append(
                    f"{manifest_path.name}: unresolved evidence_id {evidence_id!r}"
                )
    return errors


def validate_helpdesk_not_positive_evidence(dataset_root: Path) -> list[str]:
    """Ensure helpdesk ticket ids never appear as positive manifest evidence claims."""
    staging_data = _latest_agent_data_root(dataset_root)
    if staging_data is None:
        return ["agent data tree missing; cannot validate helpdesk exclusion"]

    ticket_ids = _collect_helpdesk_ticket_ids(staging_data)
    if not ticket_ids:
        return []

    manifests_dir = dataset_root / "grader" / "manifests"
    errors: list[str] = []
    for manifest_path in sorted(manifests_dir.glob("*.json")):
        if manifest_path.name.endswith("_ged_spec.json"):
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        claimed = _collect_manifest_positive_claim_ids(manifest)
        overlap = sorted(ticket_ids & claimed)
        if overlap:
            errors.append(
                f"{manifest_path.name}: helpdesk ticket ids listed as evidence claims: {overlap}"
            )
    return errors


def validate_dp2_agent_clean(dataset_root: Path) -> list[str]:
    """Ensure agent tree contains no DP2 fields or grader artifacts."""
    agent_root = dataset_root / "agent"
    if not agent_root.is_dir():
        return [f"missing agent root: {agent_root}"]
    return find_dp2_violations(agent_root)


def validate_causality_respects_stage_order(dataset_root: Path) -> list[str]:
    """Ensure staged claims and agent records do not reference future-stage evidence."""
    events_path = dataset_root / "grader" / "canonical_events.ndjson"
    if not events_path.is_file():
        return [f"missing canonical events: {events_path}"]

    events = load_canonical_events(events_path)
    events_by_id = index_by_evidence_id(events)
    origin = resolve_window_start(events, None)
    stage_minutes = _manifest_stage_minutes(dataset_root)
    errors: list[str] = []

    errors.extend(_validate_staged_manifest_causality(dataset_root, events_by_id, origin, stage_minutes))
    errors.extend(_validate_agent_linked_causality(dataset_root, events_by_id, origin, stage_minutes))
    errors.extend(_validate_tiger_temporal_order(dataset_root, events_by_id))
    return errors


def validate_tiger_verifiable_edges_reconstructible(dataset_root: Path) -> list[str]:
    """Ensure each Tiger verifiable edge is witnessable from agent-visible data only."""
    events_path = dataset_root / "grader" / "canonical_events.ndjson"
    tiger_manifest_path = dataset_root / "grader" / "manifests" / "tiger.json"
    agent_data = _latest_agent_data_root(dataset_root)
    if not tiger_manifest_path.is_file():
        return ["missing tiger manifest"]
    if agent_data is None:
        return ["agent data tree missing; cannot reconstruct tiger verifiable edges"]
    if not events_path.is_file():
        return [f"missing canonical events: {events_path}"]

    reference = json.loads(tiger_manifest_path.read_text(encoding="utf-8"))
    events = load_canonical_events(events_path)
    events_by_id = index_by_evidence_id(events)
    witness_index = build_agent_witness_index(agent_data)
    errors: list[str] = []

    mutated_hosts = _agent_hosts_were_mutated(events, witness_index)
    for edge in reference.get("edges", []):
        if not isinstance(edge, dict) or edge.get("edge_class") != "verifiable":
            continue
        rule = str(edge.get("rule", ""))
        parent_event = _manifest_node_event(edge.get("parent"), reference, events_by_id)
        child_event = _manifest_node_event(edge.get("child"), reference, events_by_id)
        if parent_event is None or child_event is None:
            errors.append(f"tiger.json: unresolved verifiable edge endpoints for rule {rule!r}")
            continue
        if mutated_hosts:
            if not _agent_witnesses_verifiable_edge_mutated(witness_index, parent_event, child_event, rule=rule):
                errors.append(
                    "tiger verifiable edge not reconstructible from mutated agent data: "
                    f"{rule} {parent_event.kind} -> {child_event.kind}"
                )
            continue
        if not _agent_witnesses_verifiable_edge(
            witness_index,
            parent_event,
            child_event,
            rule=rule,
        ):
            errors.append(
                "tiger verifiable edge not reconstructible from agent data: "
                f"{rule} {parent_event.host}/{parent_event.kind} -> "
                f"{child_event.host}/{child_event.kind}"
            )
    return errors


def _agent_hosts_were_mutated(events: list[CanonicalEvent], witness_index: dict[str, Any]) -> bool:
    canonical_hosts = {event.host for event in events}
    agent_hosts = witness_index["agent_hosts"]
    return agent_hosts != canonical_hosts


def _agent_witnesses_verifiable_edge_mutated(
    witness_index: dict[str, Any],
    parent: CanonicalEvent,
    child: CanonicalEvent,
    *,
    rule: str,
) -> bool:
    """Relaxed Tiger edge checks when augment renamed agent-visible hosts."""
    siem = witness_index["siem_by_host_rule"]
    if rule == "psexec_remote_service":
        has_launch = any(rid == "CORR-002" for _, rid in siem)
        has_service = any(rid == "CORR-001" for _, rid in siem)
        return has_launch and has_service
    if rule in {"file_artifact_continuity", "file_to_network", "host_interaction"}:
        return _agent_witnesses_event_mutated(witness_index, parent) and _agent_witnesses_event_mutated(
            witness_index, child
        )
    if rule == "process_parent_child":
        return any(row.get("pid") is not None and row.get("ppid") is not None for row in witness_index["process_rows"])
    return _agent_witnesses_event_mutated(witness_index, parent) and _agent_witnesses_event_mutated(
        witness_index, child
    )


def _agent_witnesses_event_mutated(witness_index: dict[str, Any], event: CanonicalEvent) -> bool:
    siem = witness_index["siem_by_host_rule"]
    for rule_id in KIND_TO_SIEM_RULES.get(event.kind, ()):
        if any(rid == rule_id for _, rid in siem):
            return True
    if event.kind == "process":
        return bool(witness_index["process_rows"])
    if event.kind == "connection":
        return bool(witness_index["connection_hosts"])
    return False


def build_agent_witness_index(agent_data_root: Path) -> dict[str, Any]:
    """Index agent-visible records for Tiger edge reconstruction checks."""
    agent_data_root = agent_data_root.resolve()
    siem_alerts = _load_ndjson(agent_data_root / "siem" / "alerts.ndjson")
    siem_by_host_rule: dict[tuple[str, str], list[dict[str, Any]]] = {}
    agent_hosts: set[str] = set()
    for alert in siem_alerts:
        host = str(alert.get("host", ""))
        rule_id = str(alert.get("rule_id", ""))
        if host:
            agent_hosts.add(host)
        siem_by_host_rule.setdefault((host, rule_id), []).append(alert)

    process_rows: list[dict[str, Any]] = []
    for path in sorted(agent_data_root.rglob("*.ndjson")):
        rel = path.relative_to(agent_data_root).as_posix()
        if not (
            rel.startswith("vss/")
            or rel.startswith("process_telemetry/")
            or rel == "siem/alerts.ndjson"
        ):
            continue
        for record in _load_ndjson(path):
            if rel == "siem/alerts.ndjson":
                continue
            process_rows.append(record)

    return {
        "siem_by_host_rule": siem_by_host_rule,
        "process_rows": process_rows,
        "agent_hosts": agent_hosts,
        "connection_hosts": {
            str(row.get("host", ""))
            for row in siem_alerts
            if SIEM_RULE_KIND.get(str(row.get("rule_id", "")), "") == "connection"
        },
    }


def _agent_witnesses_verifiable_edge(
    witness_index: dict[str, Any],
    parent: CanonicalEvent,
    child: CanonicalEvent,
    *,
    rule: str,
) -> bool:
    if not _agent_witnesses_event(witness_index, parent):
        return False
    if not _agent_witnesses_event(witness_index, child):
        return False

    if rule == "psexec_remote_service":
        siem = witness_index["siem_by_host_rule"]
        parent_host = _resolve_agent_host(parent.host, witness_index)
        child_host = _resolve_agent_host(child.host, witness_index)
        if parent_host is None or child_host is None:
            return False
        return bool(siem.get((parent_host, "CORR-002"))) and bool(siem.get((child_host, "CORR-001")))

    if rule in {"file_artifact_continuity", "file_to_network", "host_interaction"}:
        return True

    if rule == "process_parent_child":
        return _process_parent_child_witness(
            witness_index["process_rows"],
            parent,
            child,
            witness_index,
        )

    return True


def _resolve_agent_host(expected_host: str, witness_index: dict[str, Any]) -> str | None:
    """Map canonical hostnames to agent-visible hosts (supports augment host aliasing)."""
    agent_hosts: set[str] = witness_index["agent_hosts"]
    if expected_host in agent_hosts:
        return expected_host
    prefix = expected_host.rsplit("-", maxsplit=1)[0]
    matches = sorted(host for host in agent_hosts if host.startswith(f"{prefix}-"))
    if len(matches) == 1:
        return matches[0]
    return None


def _agent_witnesses_event(witness_index: dict[str, Any], event: CanonicalEvent) -> bool:
    agent_host = _resolve_agent_host(event.host, witness_index)
    if agent_host is None:
        return False

    siem = witness_index["siem_by_host_rule"]
    for rule_id in KIND_TO_SIEM_RULES.get(event.kind, ()):
        if siem.get((agent_host, rule_id)):
            return True

    if event.kind == "process":
        return _process_rows_cover_event(witness_index["process_rows"], event, agent_host=agent_host)
    if event.kind == "connection":
        for rule_id in KIND_TO_SIEM_RULES["connection"]:
            for (host, rid), alerts in siem.items():
                if rid != rule_id:
                    continue
                for alert in alerts:
                    if host == agent_host or agent_host in _alert_correlated_hosts(alert):
                        return True
        dst_port = event.fields.get("dst_port")
        if dst_port in {21, 443, 80} and witness_index["connection_hosts"]:
            return True
        return agent_host in witness_index["connection_hosts"]
    return False


def derive_observable_events_from_agent(agent_data_root: Path) -> list[CanonicalEvent]:
    """Build canonical-like event stubs using only agent-visible source fields."""
    agent_data_root = agent_data_root.resolve()
    derived: list[CanonicalEvent] = []
    counter = 0

    alerts_path = agent_data_root / "siem" / "alerts.ndjson"
    for record in _load_ndjson(alerts_path):
        rule_id = str(record.get("rule_id", ""))
        kind = SIEM_RULE_KIND.get(rule_id, "process")
        host = str(record.get("host", "UNKNOWN"))
        ts = str(record.get("ts", ""))
        if not ts:
            continue
        counter += 1
        derived.append(
            CanonicalEvent(
                evidence_id=f"AGENT-OBS-{counter:05d}",
                ts=ts,
                host=host,
                actor="agent_observable",
                kind=kind,
                fields=_fields_from_alert(record, kind),
                observed_by=["siem"],
                record_id=str(record.get("alert_id", f"alert-{counter}")),
            )
        )

    vss_root = agent_data_root / "vss"
    if vss_root.is_dir():
        for path in sorted(vss_root.rglob("*.ndjson")):
            for record in _load_ndjson(path):
                host = str(record.get("host", path.parent.name))
                ts = str(record.get("ts", ""))
                if not ts:
                    continue
                counter += 1
                derived.append(
                    CanonicalEvent(
                        evidence_id=f"AGENT-OBS-{counter:05d}",
                        ts=ts,
                        host=host,
                        actor="agent_observable",
                        kind="process",
                        fields={
                            "command_line": str(record.get("command_line", "")),
                            "process_name": str(record.get("process_name", "")),
                            "pid": record.get("pid"),
                            "ppid": record.get("ppid"),
                        },
                        observed_by=["vss"],
                        record_id=str(record.get("record_id", f"vss-{counter}")),
                    )
                )

    telemetry_path = agent_data_root / "process_telemetry" / "vss_duplicates.ndjson"
    for record in _load_ndjson(telemetry_path):
        host = str(record.get("host", "UNKNOWN"))
        ts = str(record.get("ts", ""))
        if not ts:
            continue
        counter += 1
        derived.append(
            CanonicalEvent(
                evidence_id=f"AGENT-OBS-{counter:05d}",
                ts=ts,
                host=host,
                actor="agent_observable",
                kind="process",
                fields={
                    "command_line": str(record.get("command_line", "")),
                    "process_name": str(record.get("process_name", "")),
                    "pid": record.get("pid"),
                    "ppid": record.get("ppid"),
                },
                observed_by=["process_telemetry"],
                record_id=str(record.get("record_id", f"telemetry-{counter}")),
            )
        )

    return derived


def _manifest_node_event(
    node_id: Any,
    manifest: dict[str, Any],
    events_by_id: dict[str, CanonicalEvent],
) -> CanonicalEvent | None:
    if not isinstance(node_id, str):
        return None
    evidence_id: str | None = None
    for node in manifest.get("nodes", []):
        if isinstance(node, dict) and node.get("id") == node_id:
            raw = node.get("evidence_id")
            if isinstance(raw, str):
                evidence_id = raw
            break
    if evidence_id is None:
        return None
    return events_by_id.get(evidence_id)


def _alert_correlated_hosts(alert: dict[str, Any]) -> set[str]:
    hosts = {str(alert.get("host", ""))}
    correlated = alert.get("correlated_hosts")
    if isinstance(correlated, list):
        hosts.update(str(item) for item in correlated if item)
    return {host for host in hosts if host}


def _artifacts_from_process_rows(rows: list[dict[str, Any]], host: str) -> set[str]:
    artifacts: set[str] = set()
    for row in rows:
        if str(row.get("host", "")) != host:
            continue
        for key in ("command_line", "message", "process_name"):
            value = row.get(key)
            if isinstance(value, str):
                for token in re.findall(r"([\w\-.]+\.(?:zip|7z|rar|tar|gz|dmp))", value, re.I):
                    artifacts.add(token.lower())
    return artifacts


def _process_rows_cover_event(
    rows: list[dict[str, Any]],
    event: CanonicalEvent,
    *,
    agent_host: str | None = None,
) -> bool:
    host = agent_host or event.host
    for row in rows:
        if str(row.get("host", "")) != host:
            continue
        command_line = str(row.get("command_line", "")).lower()
        canonical_cmd = str(event.fields.get("command_line", "")).lower()
        if canonical_cmd and canonical_cmd in command_line:
            return True
        process_name = str(event.fields.get("process_name", "")).lower()
        row_process = str(row.get("process_name", "")).lower()
        if process_name and process_name == row_process:
            return True
    return False


def _process_parent_child_witness(
    rows: list[dict[str, Any]],
    parent: CanonicalEvent,
    child: CanonicalEvent,
    witness_index: dict[str, Any],
) -> bool:
    parent_host = _resolve_agent_host(parent.host, witness_index)
    child_host = _resolve_agent_host(child.host, witness_index)
    if parent_host is None or child_host is None:
        return False
    parent_pid = parent.fields.get("pid")
    child_ppid = child.fields.get("ppid")
    if not isinstance(parent_pid, int) or not isinstance(child_ppid, int):
        return False
    if parent_pid != child_ppid:
        return False
    parent_seen = False
    child_seen = False
    for row in rows:
        if str(row.get("host", "")) != child_host:
            continue
        pid = row.get("pid")
        ppid = row.get("ppid")
        if pid == parent_pid:
            parent_seen = True
        if pid == child.fields.get("pid") and ppid == child_ppid:
            child_seen = True
    return parent_seen and child_seen


def _validate_staged_manifest_causality(
    dataset_root: Path,
    events_by_id: dict[str, CanonicalEvent],
    origin: Any,
    stage_minutes: int,
) -> list[str]:
    errors: list[str] = []
    manifests_dir = dataset_root / "grader" / "manifests"
    staged_tasks = ("fox.json", "goat.json", "panda.json")

    for filename in staged_tasks:
        path = manifests_dir / filename
        if not path.is_file():
            continue
        manifest = json.loads(path.read_text(encoding="utf-8"))
        for stage_payload in manifest.get("stages", []):
            if not isinstance(stage_payload, dict):
                continue
            stage_index = stage_payload.get("stage")
            if not isinstance(stage_index, int):
                continue
            for evidence_id in _collect_manifest_evidence_ids(stage_payload):
                event = events_by_id.get(evidence_id)
                if event is None:
                    continue
                event_stage = stage_of(event.ts, origin, stage_minutes=stage_minutes)
                if event_stage > stage_index:
                    errors.append(
                        f"{filename} stage {stage_index}: claim references future evidence "
                        f"{evidence_id} (event stage {event_stage})"
                    )
    return errors


def _validate_agent_linked_causality(
    dataset_root: Path,
    events_by_id: dict[str, CanonicalEvent],
    origin: Any,
    stage_minutes: int,
) -> list[str]:
    agent_root = dataset_root / "agent"
    errors: list[str] = []
    for stage_dir in sorted(agent_root.glob("stage_*")):
        if not stage_dir.is_dir():
            continue
        try:
            agent_stage = int(stage_dir.name.split("_", maxsplit=1)[1])
        except (IndexError, ValueError):
            continue
        data_root = stage_dir / "data"
        if not data_root.is_dir():
            continue
        for path in sorted(data_root.rglob("*.ndjson")):
            for record in _load_ndjson(path):
                record_stage = record.get("stage_index")
                if isinstance(record_stage, int) and record_stage > agent_stage:
                    rel = path.relative_to(agent_root).as_posix()
                    errors.append(
                        f"{rel}: record stage_index {record_stage} visible in agent stage "
                        f"{agent_stage}"
                    )
                linked_stages = linked_evidence_stage_indices(
                    record,
                    events_by_id,
                    origin,
                    stage_minutes=stage_minutes,
                )
                for linked_stage in linked_stages:
                    if linked_stage > agent_stage:
                        rel = path.relative_to(agent_root).as_posix()
                        errors.append(
                            f"{rel}: linked evidence from stage {linked_stage} visible in "
                            f"agent stage {agent_stage}"
                        )
    return errors


def _validate_tiger_temporal_order(
    dataset_root: Path,
    events_by_id: dict[str, CanonicalEvent],
) -> list[str]:
    tiger_path = dataset_root / "grader" / "manifests" / "tiger.json"
    if not tiger_path.is_file():
        return []

    manifest = json.loads(tiger_path.read_text(encoding="utf-8"))
    node_ts: dict[str, str] = {}
    for node in manifest.get("nodes", []):
        if isinstance(node, dict) and isinstance(node.get("id"), str):
            node_ts[node["id"]] = str(node.get("ts", ""))

    errors: list[str] = []
    for edge in manifest.get("edges", []):
        if not isinstance(edge, dict):
            continue
        parent_id = edge.get("parent")
        child_id = edge.get("child")
        if not isinstance(parent_id, str) or not isinstance(child_id, str):
            continue
        parent_ts = node_ts.get(parent_id)
        child_ts = node_ts.get(child_id)
        if not parent_ts or not child_ts:
            continue
        if parse_ts(parent_ts) > parse_ts(child_ts):
            errors.append(
                f"tiger.json: edge {edge.get('id')} parent ts {parent_ts} after child ts {child_ts}"
            )
    return errors


def _verifiable_edge_keys(
    manifest: dict[str, Any],
    events: list[CanonicalEvent],
) -> set[tuple[str, str, str, str, str]]:
    """Return verifiable edge fingerprints using observable host/kind pairs only."""
    events_by_id = index_by_evidence_id(events)
    keys: set[tuple[str, str, str, str, str]] = set()
    for edge in manifest.get("edges", []):
        if not isinstance(edge, dict) or edge.get("edge_class") != "verifiable":
            continue
        rule = str(edge.get("rule", ""))
        parent = _node_observable_signature(edge.get("parent"), manifest, events_by_id)
        child = _node_observable_signature(edge.get("child"), manifest, events_by_id)
        if parent is None or child is None:
            continue
        keys.add((rule, *parent, *child))
    return keys


def _node_observable_signature(
    node_id: Any,
    manifest: dict[str, Any],
    events_by_id: dict[str, CanonicalEvent],
) -> tuple[str, str] | None:
    if not isinstance(node_id, str):
        return None
    evidence_id: str | None = None
    for node in manifest.get("nodes", []):
        if isinstance(node, dict) and node.get("id") == node_id:
            raw = node.get("evidence_id")
            if isinstance(raw, str):
                evidence_id = raw
            host = str(node.get("host", ""))
            kind = str(node.get("kind", ""))
            if host and kind:
                return host, kind
            break
    if evidence_id and evidence_id in events_by_id:
        event = events_by_id[evidence_id]
        return event.host, event.kind
    return None


def _collect_manifest_evidence_ids(value: Any, *, key: str | None = None) -> set[str]:
    found: set[str] = set()
    if key in _EVIDENCE_ID_KEYS:
        if isinstance(value, str) and EVIDENCE_ID_PATTERN.fullmatch(value):
            found.add(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and EVIDENCE_ID_PATTERN.fullmatch(item):
                    found.add(item)
    if isinstance(value, dict):
        for nested_key, nested_value in value.items():
            found.update(_collect_manifest_evidence_ids(nested_value, key=nested_key))
    elif isinstance(value, list):
        for item in value:
            found.update(_collect_manifest_evidence_ids(item))
    return found


def _collect_manifest_positive_claim_ids(value: Any, *, key: str | None = None) -> set[str]:
    """Collect every string claim under manifest evidence-id keys (includes helpdesk ids)."""
    found: set[str] = set()
    if key in _EVIDENCE_ID_KEYS:
        if isinstance(value, str) and value.strip():
            found.add(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    found.add(item)
    if isinstance(value, dict):
        for nested_key, nested_value in value.items():
            found.update(_collect_manifest_positive_claim_ids(nested_value, key=nested_key))
    elif isinstance(value, list):
        for item in value:
            found.update(_collect_manifest_positive_claim_ids(item))
    return found


def _collect_helpdesk_ticket_ids(data_root: Path) -> set[str]:
    tickets_path = data_root / "helpdesk" / "tickets.ndjson"
    ticket_ids: set[str] = set()
    for record in _load_ndjson(tickets_path):
        ticket_id = record.get("ticket_id")
        if isinstance(ticket_id, str) and HELPDESK_TICKET_PATTERN.match(ticket_id):
            ticket_ids.add(ticket_id)
    return ticket_ids


def _latest_agent_data_root(dataset_root: Path) -> Path | None:
    agent_root = dataset_root / "agent"
    stage_dirs = sorted(agent_root.glob("stage_*"))
    if stage_dirs:
        data_root = stage_dirs[-1] / "data"
        return data_root if data_root.is_dir() else None
    data_root = agent_root / "data"
    return data_root if data_root.is_dir() else None


def _manifest_stage_minutes(dataset_root: Path) -> int:
    for path in (dataset_root / "grader" / "manifests").glob("*.json"):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        stage_minutes = manifest.get("stage_minutes")
        if isinstance(stage_minutes, int):
            return stage_minutes
    return DEFAULT_STAGE_MINUTES


def _fields_from_alert(record: dict[str, Any], kind: str) -> dict[str, Any]:
    summary = str(record.get("summary", ""))
    fields: dict[str, Any] = {"summary": summary}
    correlated = record.get("correlated_hosts")
    if isinstance(correlated, list) and correlated:
        fields["target_server"] = str(correlated[0])
    if kind == "process":
        fields["command_line"] = summary
    return fields


def _load_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        payload = json.loads(stripped)
        if isinstance(payload, dict):
            records.append(payload)
    return records
