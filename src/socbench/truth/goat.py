"""Goat task truth projector (O1..O4 ransomware impact objectives)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from evidenceforge.utils.paths import safe_write_text
from socbench.capture.models import CanonicalEvent
from socbench.truth.common import (
    DEFAULT_STAGE_MINUTES,
    estimate_share_total_bytes,
    events_through_stage,
    extract_encrypt_paths,
    infer_window_start,
    is_ransomware_event,
    is_vss_delete_event,
    load_canonical_events,
    normalize_hostname,
    parse_share_path,
    parse_ts,
    stage_end_ts,
    stage_of,
)

GOAT_MANIFEST_FILENAME = "goat.json"

GOAT_BYTE_TOLERANCE_FRACTION = 0.10
GOAT_TIME_TOLERANCE_MINUTES = 5
GOAT_DIR_FRACTION_TOLERANCE = 0.10

PathStatus = Literal["encrypted", "not_yet_encrypted"]


def build_goat_manifest(
    events: list[CanonicalEvent],
    *,
    window_start: str | None = None,
    stage_minutes: int = DEFAULT_STAGE_MINUTES,
) -> dict[str, Any]:
    """Build Goat ransomware-impact ground truth from canonical events."""
    if not events:
        return _empty_manifest(stage_minutes=stage_minutes)

    origin = parse_ts(window_start) if window_start else infer_window_start(events)
    max_stage = max(stage_of(event.ts, origin, stage_minutes=stage_minutes) for event in events)

    encrypt_targets = _collect_encrypt_targets(events)
    vss_events = _collect_vss_events(events)
    attribution = _collect_attribution(events)

    stages: list[dict[str, Any]] = []
    for stage in range(max_stage + 1):
        stage_end = parse_ts(stage_end_ts(origin, stage, stage_minutes=stage_minutes))
        cumulative = events_through_stage(events, stage, origin, stage_minutes=stage_minutes)
        encrypted_paths = _stage_encrypted_paths(encrypt_targets, stage_end)
        impact = _stage_impact_by_host_share(encrypted_paths)
        stages.append(
            {
                "stage": stage,
                "stage_end": stage_end_ts(origin, stage, stage_minutes=stage_minutes),
                "o1_encrypted_paths": encrypted_paths,
                "o2_impact_by_host_share": impact,
            }
        )

    return {
        "task": "goat",
        "schema_version": 1,
        "window_start": origin.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stage_minutes": stage_minutes,
        "manifest_thresholds": {
            "byte_tolerance_fraction": GOAT_BYTE_TOLERANCE_FRACTION,
            "time_tolerance_minutes": GOAT_TIME_TOLERANCE_MINUTES,
            "dir_fraction_tolerance": GOAT_DIR_FRACTION_TOLERANCE,
        },
        "o3_vss_events": vss_events,
        "o4_attribution": attribution,
        "stages": stages,
        "assumptions": {
            "encrypt_path_detection": (
                "UNC paths parsed from observable encryptor process command_line only"
            ),
            "vss_detection": (
                "vssadmin delete shadows process commands from observable fields"
            ),
            "share_byte_estimates": (
                "total_bytes per share are deterministic placeholders until "
                "hostmetrics source provides measured volumes"
            ),
            "attribution_fields": (
                "pid/ppid/cmdline taken from canonical process fields after backfill"
            ),
            "observation_status": (
                "Goat objectives use observable kind/fields regardless of "
                "observation_status"
            ),
        },
    }


def write_goat_manifest(manifest: dict[str, Any], output_path: Path) -> Path:
    """Write Goat manifest JSON to disk."""
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    safe_write_text(output_path, json.dumps(manifest, indent=2, sort_keys=False) + "\n")
    return output_path


def build_goat_manifest_from_file(
    events_path: Path,
    *,
    window_start: str | None = None,
    stage_minutes: int = DEFAULT_STAGE_MINUTES,
) -> dict[str, Any]:
    """Load canonical events and build the Goat manifest."""
    events = load_canonical_events(events_path)
    return build_goat_manifest(
        events,
        window_start=window_start,
        stage_minutes=stage_minutes,
    )


def _collect_encrypt_targets(events: list[CanonicalEvent]) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    for event in events:
        if not is_ransomware_event(event):
            continue
        for unc_path in extract_encrypt_paths(event):
            host, share, full_path = parse_share_path(unc_path)
            targets.append(
                {
                    "path": full_path,
                    "host": host or normalize_hostname(event.host),
                    "share": share,
                    "encrypted_at": event.ts,
                    "evidence_id": event.evidence_id,
                }
            )
    return sorted(targets, key=lambda item: (item["encrypted_at"], item["path"]))


def _collect_vss_events(events: list[CanonicalEvent]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for event in events:
        if not is_vss_delete_event(event):
            continue
        records.append(
            {
                "host": normalize_hostname(event.host),
                "event_type": "delete_shadows",
                "time": event.ts,
                "evidence_id": event.evidence_id,
            }
        )
    return sorted(records, key=lambda item: item["time"])


def _collect_attribution(events: list[CanonicalEvent]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for event in events:
        if not is_ransomware_event(event):
            continue
        fields = event.fields
        records.append(
            {
                "host": normalize_hostname(event.host),
                "pid": fields.get("pid"),
                "ppid": fields.get("ppid"),
                "process_name": fields.get("process_name"),
                "command_line": fields.get("command_line"),
                "time": event.ts,
                "evidence_id": event.evidence_id,
            }
        )
    return sorted(records, key=lambda item: item["time"])


def _stage_encrypted_paths(
    encrypt_targets: list[dict[str, Any]],
    stage_end: Any,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for target in encrypt_targets:
        encrypted_at = parse_ts(target["encrypted_at"])
        status: PathStatus = "encrypted" if encrypted_at <= stage_end else "not_yet_encrypted"
        rows.append(
            {
                "path": target["path"],
                "host": target["host"],
                "share": target["share"],
                "status": status,
                "encrypted_at": target["encrypted_at"] if status == "encrypted" else None,
                "evidence_id": target["evidence_id"] if status == "encrypted" else None,
            }
        )
    return rows


def _stage_impact_by_host_share(encrypted_paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    aggregates: dict[tuple[str, str], dict[str, Any]] = {}
    for row in encrypted_paths:
        host = str(row["host"])
        share = str(row["share"])
        key = (host, share)
        entry = aggregates.setdefault(
            key,
            {
                "host": host,
                "share": share,
                "encrypted_paths": 0,
                "total_paths_seen": 0,
                "total_bytes": estimate_share_total_bytes(host, share),
                "encrypted_bytes": 0,
            },
        )
        entry["total_paths_seen"] += 1
        if row["status"] == "encrypted":
            entry["encrypted_paths"] += 1

    impact_rows: list[dict[str, Any]] = []
    for entry in sorted(aggregates.values(), key=lambda item: (item["host"], item["share"])):
        total_bytes = int(entry["total_bytes"])
        fraction = entry["encrypted_paths"] / entry["total_paths_seen"]
        encrypted_bytes = int(total_bytes * fraction)
        impact_rows.append(
            {
                "host": entry["host"],
                "share": entry["share"],
                "encrypted_bytes": encrypted_bytes,
                "total_bytes": total_bytes,
                "encrypted_fraction": round(fraction, 4),
            }
        )
    return impact_rows


def _empty_manifest(*, stage_minutes: int) -> dict[str, Any]:
    return {
        "task": "goat",
        "schema_version": 1,
        "window_start": None,
        "stage_minutes": stage_minutes,
        "manifest_thresholds": {
            "byte_tolerance_fraction": GOAT_BYTE_TOLERANCE_FRACTION,
            "time_tolerance_minutes": GOAT_TIME_TOLERANCE_MINUTES,
            "dir_fraction_tolerance": GOAT_DIR_FRACTION_TOLERANCE,
        },
        "o3_vss_events": [],
        "o4_attribution": [],
        "stages": [],
        "assumptions": {
            "encrypt_path_detection": "UNC paths from encryptor command_line",
            "vss_detection": "vssadmin delete shadows commands",
        },
    }
