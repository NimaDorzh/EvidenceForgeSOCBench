"""Tiger task truth projector (threat graph + verifiable/contextual edges)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

from evidenceforge.utils.paths import safe_write_text
from socbench.capture.models import CanonicalEvent
from socbench.truth.common import (
    extract_file_artifacts_from_event,
    is_initial_access_event,
    is_psexec_helper_service,
    is_psexec_launcher_event,
    load_canonical_events,
    normalize_file_artifact,
    normalize_hostname,
    parse_ts,
    psexec_target_hosts,
)

TIGER_MANIFEST_FILENAME = "tiger.json"
TIGER_GED_SPEC_FILENAME = "tiger_ged_spec.json"

PSEXEC_SERVICE_WINDOW_MINUTES = 15
FILE_ARTIFACT_WINDOW_MINUTES = 45
AUTH_SESSION_WINDOW_MINUTES = 120
SEQUENTIAL_CONTEXT_WINDOW_MINUTES = 30

EdgeClass = Literal["verifiable", "contextual"]


@dataclass(frozen=True, slots=True)
class GraphNode:
    """One canonical event vertex."""

    node_id: str
    evidence_id: str
    host: str
    kind: str
    ts: str
    record_id: str | None


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """Directed graph edge with verifiability classification."""

    edge_id: str
    parent_id: str
    child_id: str
    interaction: str
    edge_class: EdgeClass
    rule: str
    evidence_ids: tuple[str, ...]
    source_attribution: tuple[str, ...]


def build_tiger_manifest(events: list[CanonicalEvent]) -> dict[str, Any]:
    """Build Tiger threat graph manifest from canonical events."""
    nodes = [_node_from_event(event) for event in events]
    node_by_evidence = {node.evidence_id: node for node in nodes}

    verifiable = _build_verifiable_edges(events, node_by_evidence)
    contextual = _build_contextual_edges(events, node_by_evidence, verifiable)
    all_edges = verifiable + contextual

    relevant_sources = sorted(
        {
            source
            for event in events
            for source in event.observed_by
            if event.observed_by
        }
    )
    entrypoint = _initial_entrypoint(events)

    manifest = {
        "task": "tiger",
        "schema_version": 1,
        "o1_relevant_sources": {
            "sources": relevant_sources,
            "trap_sources": [],
        },
        "o3_initial_entrypoint": entrypoint,
        "forbidden_evidence_ids": [],
        "nodes": [
            {
                "id": node.node_id,
                "evidence_id": node.evidence_id,
                "host": node.host,
                "kind": node.kind,
                "ts": node.ts,
                "record_id": node.record_id,
            }
            for node in nodes
        ],
        "edges": [_edge_payload(edge) for edge in all_edges],
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(all_edges),
            "verifiable_edge_count": len(verifiable),
            "contextual_edge_count": len(contextual),
        },
        "assumptions": {
            "verifiable_rules": [
                "process_parent_child",
                "psexec_remote_service",
                "auth_session_action",
                "file_artifact_continuity",
                "file_to_network",
                "host_interaction",
            ],
            "contextual_rules": [
                "sequential_tools_same_host",
                "lateral_shared_source_ip",
            ],
            "observation_status": (
                "Edge detection uses observable kind/fields only; grader phase/attack ignored"
            ),
            "forensics_reference": "docs/worklog/2026-07-11-tiger-verifiable-rules-colonial.md",
        },
    }
    return manifest


def build_tiger_ged_spec() -> dict[str, Any]:
    """Return GED scoring weights for grader use."""
    weights = {
        "verifiable_edge_missing": 5.0,
        "verifiable_edge_extra": 4.0,
        "contextual_edge_missing": 1.0,
        "contextual_edge_extra": 0.5,
        "node_missing": 2.0,
        "node_extra": 1.0,
    }
    return {
        "schema_version": 1,
        "task": "tiger",
        "metric": "graph_edit_distance",
        "weights": weights,
        "weight_ratios": {
            "verifiable_missing_vs_contextual_missing": (
                weights["verifiable_edge_missing"] / weights["contextual_edge_missing"]
            ),
            "verifiable_missing_vs_contextual_extra": (
                weights["verifiable_edge_missing"] / weights["contextual_edge_extra"]
            ),
            "verifiable_extra_vs_contextual_extra": (
                weights["verifiable_edge_extra"] / weights["contextual_edge_extra"]
            ),
        },
        "hard_match": {
            "verifiable_edges": True,
            "contextual_edges": False,
        },
        "notes": (
            "Agent graph is scored softly via weighted GED; verifiable-edge subset "
            "must match exactly for full credit on the hard core. "
            "Verifiable delete/miss weights are ≥5× contextual counterparts."
        ),
    }


def score_graph_edit_distance(
    candidate: dict[str, Any],
    reference: dict[str, Any],
    *,
    spec: dict[str, Any] | None = None,
) -> float:
    """Compute weighted GED-style cost between candidate and reference Tiger graphs."""
    ged_spec = spec or build_tiger_ged_spec()
    weights: dict[str, float] = ged_spec["weights"]

    def edge_keys(manifest: dict[str, Any], edge_class: str) -> set[tuple[str, str, str]]:
        return {
            (edge["parent"], edge["child"], edge["rule"])
            for edge in manifest.get("edges", [])
            if edge.get("edge_class") == edge_class
        }

    def node_ids(manifest: dict[str, Any]) -> set[str]:
        return {node["id"] for node in manifest.get("nodes", [])}

    cost = 0.0
    for edge_class, missing_key, extra_key in (
        ("verifiable", "verifiable_edge_missing", "verifiable_edge_extra"),
        ("contextual", "contextual_edge_missing", "contextual_edge_extra"),
    ):
        ref_edges = edge_keys(reference, edge_class)
        cand_edges = edge_keys(candidate, edge_class)
        cost += len(ref_edges - cand_edges) * weights[missing_key]
        cost += len(cand_edges - ref_edges) * weights[extra_key]

    ref_nodes = node_ids(reference)
    cand_nodes = node_ids(candidate)
    cost += len(ref_nodes - cand_nodes) * weights["node_missing"]
    cost += len(cand_nodes - ref_nodes) * weights["node_extra"]
    return cost


def write_tiger_manifest(manifest: dict[str, Any], output_path: Path) -> Path:
    """Write Tiger manifest JSON to disk."""
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    safe_write_text(output_path, json.dumps(manifest, indent=2, sort_keys=False) + "\n")
    return output_path


def write_tiger_ged_spec(spec: dict[str, Any], output_path: Path) -> Path:
    """Write Tiger GED spec JSON alongside the manifest."""
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    safe_write_text(output_path, json.dumps(spec, indent=2, sort_keys=False) + "\n")
    return output_path


def build_tiger_manifest_from_file(events_path: Path) -> dict[str, Any]:
    """Load canonical events and build the Tiger manifest."""
    return build_tiger_manifest(load_canonical_events(events_path))


def _node_from_event(event: CanonicalEvent) -> GraphNode:
    return GraphNode(
        node_id=f"N-{event.evidence_id}",
        evidence_id=event.evidence_id,
        host=normalize_hostname(event.host),
        kind=event.kind,
        ts=event.ts,
        record_id=event.record_id,
    )


def _edge_payload(edge: GraphEdge) -> dict[str, Any]:
    return {
        "id": edge.edge_id,
        "parent": edge.parent_id,
        "child": edge.child_id,
        "interaction": edge.interaction,
        "edge_class": edge.edge_class,
        "rule": edge.rule,
        "evidence_ids": list(edge.evidence_ids),
        "source_attribution": list(edge.source_attribution),
    }


def _merge_attribution(left: CanonicalEvent, right: CanonicalEvent) -> tuple[str, ...]:
    merged = sorted(set(left.observed_by) | set(right.observed_by))
    return tuple(merged)


def _build_verifiable_edges(
    events: list[CanonicalEvent],
    node_by_evidence: dict[str, GraphNode],
) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    counter = 1

    def add_edge(
        *,
        parent: CanonicalEvent,
        child: CanonicalEvent,
        interaction: str,
        rule: str,
    ) -> None:
        nonlocal counter
        parent_node = node_by_evidence[parent.evidence_id]
        child_node = node_by_evidence[child.evidence_id]
        edges.append(
            GraphEdge(
                edge_id=f"E{counter}",
                parent_id=parent_node.node_id,
                child_id=child_node.node_id,
                interaction=interaction,
                edge_class="verifiable",
                rule=rule,
                evidence_ids=(parent.evidence_id, child.evidence_id),
                source_attribution=_merge_attribution(parent, child),
            )
        )
        counter += 1

    pid_index: dict[tuple[str, int], CanonicalEvent] = {}
    for event in events:
        pid = event.fields.get("pid")
        if isinstance(pid, int):
            pid_index[(normalize_hostname(event.host), pid)] = event

    for event in events:
        ppid = event.fields.get("ppid")
        pid = event.fields.get("pid")
        if not isinstance(ppid, int) or not isinstance(pid, int):
            continue
        parent = pid_index.get((normalize_hostname(event.host), ppid))
        if parent is None:
            continue
        add_edge(
            parent=parent,
            child=event,
            interaction="process_parent_child",
            rule="process_parent_child",
        )

    service_events = [event for event in events if is_psexec_helper_service(event)]
    for launcher in [event for event in events if is_psexec_launcher_event(event)]:
        launch_time = parse_ts(launcher.ts)
        targets = psexec_target_hosts(launcher)
        for service in service_events:
            if normalize_hostname(service.host) not in targets:
                continue
            if parse_ts(service.ts) < launch_time:
                continue
            if parse_ts(service.ts) - launch_time > timedelta(minutes=PSEXEC_SERVICE_WINDOW_MINUTES):
                continue
            add_edge(
                parent=launcher,
                child=service,
                interaction="psexec_remote_service",
                rule="psexec_remote_service",
            )

    logon_index: dict[tuple[str, str], list[CanonicalEvent]] = {}
    for event in events:
        logon_id = event.fields.get("logon_id")
        if not isinstance(logon_id, str) or not logon_id:
            continue
        logon_index.setdefault((normalize_hostname(event.host), logon_id), []).append(event)

    for keyed_events in logon_index.values():
        anchor = min(keyed_events, key=lambda event: parse_ts(event.ts))
        if anchor.kind not in {"logon", "explicit_credentials"}:
            continue
        anchor_time = parse_ts(anchor.ts)
        for event in events:
            if normalize_hostname(event.host) != normalize_hostname(anchor.host):
                continue
            if event.fields.get("logon_id") != anchor.fields.get("logon_id"):
                continue
            if event.evidence_id == anchor.evidence_id:
                continue
            if event.kind not in {"process", "service_installed", "connection"}:
                continue
            if parse_ts(event.ts) < anchor_time:
                continue
            if parse_ts(event.ts) - anchor_time > timedelta(minutes=AUTH_SESSION_WINDOW_MINUTES):
                continue
            add_edge(
                parent=anchor,
                child=event,
                interaction="auth_session_action",
                rule="auth_session_action",
            )

    process_events = [event for event in events if event.kind == "process"]
    for left in process_events:
        left_artifacts = extract_file_artifacts_from_event(left)
        if not left_artifacts:
            continue
        left_time = parse_ts(left.ts)
        for right in process_events:
            if left.evidence_id == right.evidence_id:
                continue
            if normalize_hostname(left.host) != normalize_hostname(right.host):
                continue
            shared = left_artifacts & extract_file_artifacts_from_event(right)
            if not shared:
                continue
            right_time = parse_ts(right.ts)
            if right_time <= left_time:
                continue
            if right_time - left_time > timedelta(minutes=FILE_ARTIFACT_WINDOW_MINUTES):
                continue
            artifact = normalize_file_artifact(next(iter(shared)))
            add_edge(
                parent=left,
                child=right,
                interaction=f"file_artifact:{artifact}",
                rule="file_artifact_continuity",
            )

    connection_events = [event for event in events if event.kind == "connection"]
    for process in process_events:
        if not extract_file_artifacts_from_event(process):
            continue
        process_time = parse_ts(process.ts)
        for connection in connection_events:
            if normalize_hostname(connection.host) != normalize_hostname(process.host):
                continue
            if connection.fields.get("dst_port") not in {21, 443, 80}:
                continue
            connection_time = parse_ts(connection.ts)
            if connection_time < process_time:
                continue
            if connection_time - process_time > timedelta(minutes=FILE_ARTIFACT_WINDOW_MINUTES):
                continue
            add_edge(
                parent=process,
                child=connection,
                interaction="file_to_network",
                rule="file_to_network",
            )

    return _dedupe_edges(edges)


def _build_contextual_edges(
    events: list[CanonicalEvent],
    node_by_evidence: dict[str, GraphNode],
    verifiable: list[GraphEdge],
) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    counter = 1
    verifiable_pairs = {(edge.parent_id, edge.child_id) for edge in verifiable}

    def add_contextual(parent: CanonicalEvent, child: CanonicalEvent, rule: str) -> None:
        nonlocal counter
        parent_node = node_by_evidence[parent.evidence_id]
        child_node = node_by_evidence[child.evidence_id]
        pair = (parent_node.node_id, child_node.node_id)
        if pair in verifiable_pairs:
            return
        edges.append(
            GraphEdge(
                edge_id=f"C{counter}",
                parent_id=parent_node.node_id,
                child_id=child_node.node_id,
                interaction=rule,
                edge_class="contextual",
                rule=rule,
                evidence_ids=(parent.evidence_id, child.evidence_id),
                source_attribution=_merge_attribution(parent, child),
            )
        )
        counter += 1

    process_events = sorted(
        [event for event in events if event.kind == "process"],
        key=lambda event: parse_ts(event.ts),
    )
    for left in process_events:
        for right in process_events:
            if left.evidence_id == right.evidence_id:
                continue
            if normalize_hostname(left.host) != normalize_hostname(right.host):
                continue
            if left.kind != "process" or right.kind != "process":
                continue
            delta = parse_ts(right.ts) - parse_ts(left.ts)
            if delta <= timedelta(0):
                continue
            if delta > timedelta(minutes=SEQUENTIAL_CONTEXT_WINDOW_MINUTES):
                continue
            add_contextual(left, right, "sequential_tools_same_host")

    logons = [event for event in events if event.kind == "logon"]
    for left in logons:
        for right in logons:
            if left.evidence_id == right.evidence_id:
                continue
            left_ip = left.fields.get("source_ip")
            right_ip = right.fields.get("source_ip")
            if not isinstance(left_ip, str) or left_ip != right_ip:
                continue
            if normalize_hostname(left.host) == normalize_hostname(right.host):
                continue
            if parse_ts(right.ts) < parse_ts(left.ts):
                continue
            add_contextual(left, right, "lateral_shared_source_ip")

    return _dedupe_edges(edges)


def _dedupe_edges(edges: list[GraphEdge]) -> list[GraphEdge]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[GraphEdge] = []
    for edge in edges:
        key = (edge.parent_id, edge.child_id, edge.rule, edge.edge_class)
        if key in seen:
            continue
        seen.add(key)
        unique.append(edge)
    return unique


def _initial_entrypoint(events: list[CanonicalEvent]) -> dict[str, Any] | None:
    candidates = [event for event in events if is_initial_access_event(event)]
    if not candidates:
        return None
    first = min(candidates, key=lambda event: parse_ts(event.ts))
    return {
        "evidence_id": first.evidence_id,
        "ts": first.ts,
        "host": normalize_hostname(first.host),
        "kind": first.kind,
        "source_ip": first.fields.get("source_ip"),
        "dst_ip": first.fields.get("dst_ip"),
    }
