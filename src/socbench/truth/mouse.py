"""Mouse task truth projector (O1..O5 exfiltration objectives)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidenceforge.utils.paths import safe_write_text
from socbench.capture.models import CanonicalEvent
from socbench.truth.common import (
    connection_bytes,
    is_exfil_connection_event,
    is_staging_event,
    load_canonical_events,
    parse_ts,
    protocol_label,
)

MOUSE_MANIFEST_FILENAME = "mouse.json"

MOUSE_START_TIME_TOLERANCE_MINUTES = 5
MOUSE_VOLUME_TOLERANCE_GB = 10
MOUSE_INVOLVED_HOSTS_TOLERANCE = 3


def build_mouse_manifest(events: list[CanonicalEvent]) -> dict[str, Any]:
    """Build Mouse exfiltration ground truth from canonical events."""
    exfil_events = [event for event in events if is_exfil_connection_event(event)]
    staging_events = [event for event in events if is_staging_event(event)]
    exfil_happens = bool(exfil_events)

    if not exfil_happens:
        return _no_exfil_manifest()

    start_event = min(exfil_events, key=lambda event: parse_ts(event.ts))
    protocol_volumes: dict[str, int] = {}
    for event in exfil_events:
        label = protocol_label(event)
        protocol_volumes[label] = protocol_volumes.get(label, 0) + connection_bytes(event)

    total_bytes = sum(protocol_volumes.values())
    primary_protocol = max(protocol_volumes, key=protocol_volumes.get)

    involved_hosts = sorted(
        {event.host for event in exfil_events} | {event.host for event in staging_events}
    )

    return {
        "task": "mouse",
        "schema_version": 1,
        "exfil_happens": True,
        "o1_exfil_occurred": "Yes",
        "o2_start_time": start_event.ts,
        "o3_volume_gb": round(total_bytes / (1024**3), 3),
        "o4_involved_hosts": involved_hosts,
        "o5_protocols": {
            "primary": primary_protocol,
            "channels": [
                {
                    "protocol": protocol,
                    "bytes": byte_count,
                    "volume_gb": round(byte_count / (1024**3), 3),
                }
                for protocol, byte_count in sorted(protocol_volumes.items())
            ],
        },
        "tolerances": {
            "start_time_minutes": MOUSE_START_TIME_TOLERANCE_MINUTES,
            "volume_gb": MOUSE_VOLUME_TOLERANCE_GB,
            "involved_hosts": MOUSE_INVOLVED_HOSTS_TOLERANCE,
        },
        "evidence_ids": {
            "exfiltration": [event.evidence_id for event in exfil_events],
            "staging": [event.evidence_id for event in staging_events],
            "o2_start": start_event.evidence_id,
        },
        "assumptions": {
            "exfil_detection": (
                "connection events to non-internal dst_ip with outbound bytes or ports 21/443"
            ),
            "staging_detection": (
                "internal ftp/smb connections or archive/upload process commands"
            ),
            "observation_status": (
                "O1..O5 aggregates include all matching events regardless of "
                "observation_status; only kind/fields/ts/host matter"
            ),
        },
    }


def write_mouse_manifest(manifest: dict[str, Any], output_path: Path) -> Path:
    """Write Mouse manifest JSON to disk."""
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    safe_write_text(output_path, json.dumps(manifest, indent=2, sort_keys=False) + "\n")
    return output_path


def build_mouse_manifest_from_file(events_path: Path) -> dict[str, Any]:
    """Load canonical events and build the Mouse manifest."""
    return build_mouse_manifest(load_canonical_events(events_path))


def _no_exfil_manifest() -> dict[str, Any]:
    return {
        "task": "mouse",
        "schema_version": 1,
        "exfil_happens": False,
        "o1_exfil_occurred": "No",
        "o2_start_time": None,
        "o3_volume_gb": None,
        "o4_involved_hosts": None,
        "o5_protocols": None,
        "tolerances": {
            "start_time_minutes": MOUSE_START_TIME_TOLERANCE_MINUTES,
            "volume_gb": MOUSE_VOLUME_TOLERANCE_GB,
            "involved_hosts": MOUSE_INVOLVED_HOSTS_TOLERANCE,
        },
        "evidence_ids": {},
        "assumptions": {
            "exfil_detection": (
                "connection events to non-internal dst_ip with outbound bytes or ports 21/443"
            ),
        },
    }
