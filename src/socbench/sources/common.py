"""Shared helpers for SOC-bench synthetic source builders."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, timedelta
from pathlib import Path
from typing import Any

from evidenceforge.utils.paths import safe_write_text
from socbench.capture.models import CanonicalEvent
from socbench.sources.models import (
    GraderMetadata,
    SourceBuildConfig,
    SourceBuildResult,
    SourceRecord,
)
from socbench.sources.text import LlmTextCache
from socbench.truth.common import (
    is_exfil_connection_event,
    is_ransomware_event,
    is_vss_delete_event,
    load_canonical_events,
    parse_ts,
    resolve_window_start,
    stage_of,
)

SOURCE_NAMES = ("siem", "hostmetrics", "vss", "helpdesk", "cti")


def load_events(path: Path) -> list[CanonicalEvent]:
    """Load canonical events from NDJSON."""
    return load_canonical_events(path)


def write_source_records(path: Path, records: list[SourceRecord]) -> Path:
    """Write sorted-key NDJSON source records to disk."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(record.to_ndjson_dict(), sort_keys=True)
        for record in sorted(records, key=_record_sort_key)
    ]
    payload = "\n".join(lines)
    if payload:
        payload += "\n"
    safe_write_text(path, payload, encoding="utf-8")
    return path


def file_digest(path: Path) -> str:
    """Return SHA-256 digest of on-disk file bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def apply_latency(ts: str, latency_ms: int) -> str:
    """Shift an ISO timestamp forward by latency milliseconds."""
    shifted = parse_ts(ts) + timedelta(milliseconds=latency_ms)
    return shifted.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def grader_metadata(
    *,
    linked_evidence_ids: list[str],
    latency_applied_ms: int,
    template_id: str,
) -> GraderMetadata:
    """Build grader metadata with sorted linked ids."""
    return GraderMetadata(
        linked_evidence_ids=sorted(linked_evidence_ids),
        latency_applied_ms=latency_applied_ms,
        template_id=template_id,
    )


def attack_linked_records(records: list[SourceRecord]) -> int:
    """Count records whose grader metadata links to at least one evidence id."""
    return sum(
        1
        for record in records
        if record.grader_metadata is not None and record.grader_metadata.linked_evidence_ids
    )


def build_llm_cache(config: SourceBuildConfig) -> LlmTextCache | None:
    """Return an LLM cache when configured."""
    if config.llm_cache_path is None:
        return None
    return LlmTextCache(Path(config.llm_cache_path))


def resolve_helpdesk_min_stage(
    events: list[CanonicalEvent],
    config: SourceBuildConfig,
) -> int:
    """Return minimum stage index for helpdesk ticket emission."""
    if config.helpdesk_min_stage is not None:
        return config.helpdesk_min_stage
    if not events:
        return 0
    origin = resolve_window_start(events, config.window_start)
    max_stage = max(
        stage_of(event.ts, origin, stage_minutes=config.stage_minutes) for event in events
    )
    return max_stage // 2


def collect_hosts(events: list[CanonicalEvent]) -> list[str]:
    """Return sorted unique hostnames from canonical events."""
    return sorted({event.host for event in events})


def early_scenario_ts(
    events: list[CanonicalEvent],
    config: SourceBuildConfig,
    *,
    salt: str,
    index: int = 0,
) -> str:
    """Return a deterministic timestamp near the start of the scenario window."""
    from random import Random

    from socbench.capture.hashing import stable_seed

    origin = resolve_window_start(events, config.window_start)
    rng = Random(stable_seed(f"{salt}:{config.seed}:{index}"))
    offset_minutes = rng.randint(0, max(config.stage_minutes - 1, 0))
    shifted = origin + timedelta(minutes=offset_minutes)
    return shifted.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def pre_scenario_ts(
    events: list[CanonicalEvent],
    config: SourceBuildConfig,
    *,
    salt: str,
    index: int = 0,
) -> str:
    """Return a deterministic timestamp before the scenario window (trap/historical noise)."""
    from random import Random

    from socbench.capture.hashing import stable_seed

    origin = resolve_window_start(events, config.window_start)
    rng = Random(stable_seed(f"{salt}:{config.seed}:{index}"))
    shifted = origin - timedelta(
        days=rng.randint(1, 30),
        hours=rng.randint(0, 23),
        minutes=rng.randint(0, 59),
    )
    return shifted.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _record_sort_key(record: SourceRecord) -> tuple[str, str]:
    payload = record.payload
    ts = str(payload.get("ts", ""))
    record_id = str(payload.get("record_id", payload.get("ticket_id", payload.get("alert_id", ""))))
    return ts, record_id


def summarize_result(
    source_name: str, files: list[Path], records: list[SourceRecord]
) -> SourceBuildResult:
    return SourceBuildResult(
        source_name=source_name,
        files=[str(path) for path in files],
        record_count=len(records),
        attack_linked_count=attack_linked_records(records),
    )


def is_attack_relevant_event(event: CanonicalEvent) -> bool:
    """Return True when an event should drive attack-linked synthetic sources."""
    return (
        is_vss_delete_event(event)
        or is_ransomware_event(event)
        or is_exfil_connection_event(event)
        or event.kind in {"create_remote_thread", "service_installed", "rdp_session", "ssh_session"}
    )


def event_summary_for_slots(event: CanonicalEvent) -> dict[str, Any]:
    """Extract template slots from observable canonical fields."""
    fields = event.fields
    return {
        "host": event.host,
        "kind": event.kind,
        "evidence_id": event.evidence_id,
        "process_name": fields.get("process_name", ""),
        "command_line": fields.get("command_line", ""),
        "pid": fields.get("pid", ""),
        "dst_ip": fields.get("dst_ip", ""),
        "dst_port": fields.get("dst_port", ""),
        "service_name": fields.get("service_name", ""),
    }
