"""Fox task truth projector (o1_scale / o2_type / o3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidenceforge.utils.paths import safe_write_text
from socbench.capture.models import CanonicalEvent
from socbench.truth.common import (
    AUTH_BURST_MIN_EVENTS,
    AUTH_BURST_WINDOW_MINUTES,
    DEFAULT_STAGE_MINUTES,
    RANSOMWARE_PRECURSOR_MARKERS,
    ScaleLabel,
    TypeLabel,
    auth_burst_detected,
    build_host_interaction_graph,
    classify_scale_label,
    classify_type_label,
    distinct_precursor_categories,
    events_through_stage,
    infer_window_start,
    is_ransomware_event,
    load_canonical_events,
    normalize_hostname,
    parse_ts,
    stage_end_ts,
    stage_of,
)

FOX_MANIFEST_FILENAME = "fox.json"


def build_fox_manifest(
    events: list[CanonicalEvent],
    *,
    window_start: str | None = None,
    stage_minutes: int = DEFAULT_STAGE_MINUTES,
) -> dict[str, Any]:
    """Build cumulative per-stage Fox ground truth from canonical events."""
    if not events:
        return _empty_manifest(stage_minutes=stage_minutes)

    origin = parse_ts(window_start) if window_start else infer_window_start(events)
    max_stage = max(stage_of(event.ts, origin, stage_minutes=stage_minutes) for event in events)

    first_affected_host: str | None = None
    first_affected_evidence_id: str | None = None
    first_ransomware_ts: str | None = None
    first_ransomware_host: str | None = None
    first_ransomware_evidence_id: str | None = None

    stages: list[dict[str, Any]] = []
    for stage in range(max_stage + 1):
        cumulative = events_through_stage(events, stage, origin, stage_minutes=stage_minutes)
        if not first_affected_host:
            first_event = min(cumulative, key=lambda event: parse_ts(event.ts))
            first_affected_host = normalize_hostname(first_event.host)
            first_affected_evidence_id = first_event.evidence_id

        for event in sorted(cumulative, key=lambda item: parse_ts(item.ts)):
            if first_ransomware_evidence_id is None and is_ransomware_event(event):
                first_ransomware_ts = event.ts
                first_ransomware_host = normalize_hostname(event.host)
                first_ransomware_evidence_id = event.evidence_id

        affected_hosts, edges, graph_metadata = build_host_interaction_graph(cumulative)
        burst = auth_burst_detected(cumulative)
        scale_label = classify_scale_label(affected_hosts, edges, auth_burst=burst)
        type_label = classify_type_label(cumulative, scale_label=scale_label)
        precursor_categories = sorted(distinct_precursor_categories(cumulative))

        stages.append(
            {
                "stage": stage,
                "stage_end": stage_end_ts(origin, stage, stage_minutes=stage_minutes),
                "o1_scale": _o1_payload(
                    scale_label=scale_label,
                    affected_hosts=sorted(affected_hosts),
                    edges=sorted(
                        [{"left": left, "right": right} for left, right in edges],
                        key=lambda item: (item["left"], item["right"]),
                    ),
                    auth_burst=burst,
                    graph_metadata=graph_metadata,
                ),
                "o2_type": _o2_payload(
                    type_label=type_label,
                    precursor_categories=precursor_categories,
                ),
                "o3": {
                    "first_affected_host": first_affected_host,
                    "first_affected_evidence_id": first_affected_evidence_id,
                    "first_ransomware_event_ts": first_ransomware_ts,
                    "first_ransomware_host": first_ransomware_host,
                    "first_ransomware_evidence_id": first_ransomware_evidence_id,
                },
            }
        )

    host_adjacency_assumption = (
        "Host adjacency follows verifiable observable interactions "
        "(source_ip/logon, dst_ip connection, remote-exec hostname, shared uid/logon_id)."
    )

    return {
        "task": "fox",
        "schema_version": 1,
        "window_start": origin.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stage_minutes": stage_minutes,
        "assumptions": {
            "host_adjacency": host_adjacency_assumption,
            "auth_burst_min_events": AUTH_BURST_MIN_EVENTS,
            "auth_burst_window_minutes": AUTH_BURST_WINDOW_MINUTES,
            "precursor_markers": [
                {
                    "category": marker.category,
                    "attack_ids": sorted(marker.attack_ids),
                    "kinds": sorted(marker.kinds),
                    "windows_event_id": marker.windows_event_id,
                }
                for marker in RANSOMWARE_PRECURSOR_MARKERS
            ],
            "type_label_rules": {
                "ransomware_like": ">=2 distinct precursor categories",
                "uncertain": "0 precursor categories, or isolated activity with 1 category",
                "non_ransom_coordinated": (
                    "exactly 1 precursor category with localized/campaign_scale correlation"
                ),
            },
        },
        "stages": stages,
    }


def write_fox_manifest(manifest: dict[str, Any], output_path: Path) -> Path:
    """Write Fox manifest JSON to disk."""
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    safe_write_text(output_path, json.dumps(manifest, indent=2, sort_keys=False) + "\n")
    return output_path


def build_fox_manifest_from_file(
    events_path: Path,
    *,
    window_start: str | None = None,
    stage_minutes: int = DEFAULT_STAGE_MINUTES,
) -> dict[str, Any]:
    """Load canonical events and build the Fox manifest."""
    events = load_canonical_events(events_path)
    return build_fox_manifest(
        events,
        window_start=window_start,
        stage_minutes=stage_minutes,
    )


def _o1_payload(
    *,
    scale_label: ScaleLabel | None,
    affected_hosts: list[str],
    edges: list[dict[str, str]],
    auth_burst: bool,
    graph_metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "scale_label": scale_label,
        "affected_hosts": affected_hosts,
        "host_graph": {
            "vertices": affected_hosts,
            "edges": edges,
        },
        "auth_burst_detected": auth_burst,
        "ip_to_host": graph_metadata["ip_to_host"],
        "edge_provenance": graph_metadata["edge_records"],
    }


def _o2_payload(
    *,
    type_label: TypeLabel | None,
    precursor_categories: list[str],
) -> dict[str, Any]:
    return {
        "type_label": type_label,
        "precursor_categories": precursor_categories,
        "distinct_precursor_count": len(precursor_categories),
    }


def _empty_manifest(*, stage_minutes: int) -> dict[str, Any]:
    return {
        "task": "fox",
        "schema_version": 1,
        "window_start": None,
        "stage_minutes": stage_minutes,
        "assumptions": {
            "host_adjacency": "verifiable observable interactions",
            "auth_burst_min_events": AUTH_BURST_MIN_EVENTS,
            "auth_burst_window_minutes": AUTH_BURST_WINDOW_MINUTES,
            "precursor_markers": [
                {
                    "category": marker.category,
                    "attack_ids": sorted(marker.attack_ids),
                    "kinds": sorted(marker.kinds),
                    "windows_event_id": marker.windows_event_id,
                }
                for marker in RANSOMWARE_PRECURSOR_MARKERS
            ],
        },
        "stages": [],
    }
