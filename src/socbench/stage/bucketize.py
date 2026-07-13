"""Stage-based slicing of agent sources and canonical events."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from evidenceforge.utils.paths import safe_write_text
from socbench.capture.canonical_events import CANONICAL_EVENTS_FILENAME
from socbench.capture.models import CanonicalEvent
from socbench.raw.host_logs import bucketize_host_logs
from socbench.sources.common import file_digest
from socbench.truth.common import (
    DEFAULT_STAGE_MINUTES,
    load_canonical_events,
    resolve_window_start,
    stage_of,
)

HELPDESK_TICKETS_REL = Path("helpdesk") / "tickets.ndjson"
BUCKETIZED_DATA_SUBDIRS = (
    "siem",
    "hostmetrics",
    "vss",
    "helpdesk",
    "cti",
    "process_telemetry",
)


@dataclass(frozen=True, slots=True)
class BucketizeResult:
    """Summary of stage directories written by bucketize."""

    agent_root: Path
    stage_count: int
    stage_digests: dict[str, dict[str, str]]
    window_start: datetime
    stage_minutes: int
    max_stage: int


def bucketize_bundle(
    bundle_dir: Path,
    *,
    events_path: Path | None = None,
    agent_root: Path | None = None,
    window_start: str | datetime | None = None,
    stage_minutes: int = DEFAULT_STAGE_MINUTES,
) -> BucketizeResult:
    """Slice synthetic ``data/`` NDJSON sources and canonical events into ``agent/stage_XX/``.

    Each ``agent/stage_XX/`` directory contains cumulative records whose observable
    ``ts`` falls on or before the end of stage ``XX``, plus late-source gating:

    * **helpdesk** — records carry a precomputed ``min_stage_gate`` from step 4;
      bucketize reads it and omits tickets when ``XX < min_stage_gate``.
    * **CTI** — no ``min_stage_gate``; user-linked rows are gated by ``ts`` only.
    """
    bundle_dir = bundle_dir.resolve()
    data_root = bundle_dir / "data"
    events_file = (events_path or (bundle_dir / "grader" / CANONICAL_EVENTS_FILENAME)).resolve()
    out_root = (agent_root or (bundle_dir / "agent")).resolve()

    events = load_canonical_events(events_file)
    origin = resolve_window_start(events, window_start)

    source_files = _discover_bucketizable_files(data_root)
    source_records = {
        rel_path: _load_ndjson_records(data_root / rel_path) for rel_path in source_files
    }

    max_stage = _resolve_max_stage(events, source_records, origin, stage_minutes=stage_minutes)
    stage_digests: dict[str, dict[str, str]] = {}

    for stage in range(max_stage + 1):
        stage_dir = out_root / f"stage_{stage:02d}"
        stage_data_root = stage_dir / "data"
        stage_digests[f"stage_{stage:02d}"] = {}

        for rel_path, records in source_records.items():
            visible = [
                _annotate_stage_index(record, origin, stage_minutes=stage_minutes)
                for record in records
                if _record_visible_in_agent_stage(
                    record,
                    rel_path,
                    agent_stage=stage,
                    window_start=origin,
                    stage_minutes=stage_minutes,
                )
            ]
            if not visible:
                continue
            out_path = stage_data_root / rel_path
            _write_ndjson_records(out_path, visible)
            stage_digests[f"stage_{stage:02d}"][str(rel_path).replace("\\", "/")] = file_digest(
                out_path
            )

        canonical_slice = [
            _canonical_to_stage_dict(event, origin, stage_minutes=stage_minutes)
            for event in events
            if stage_of(event.ts, origin, stage_minutes=stage_minutes) <= stage
        ]
        if canonical_slice:
            canonical_path = stage_dir / CANONICAL_EVENTS_FILENAME
            _write_ndjson_records(canonical_path, canonical_slice)
            stage_digests[f"stage_{stage:02d}"][CANONICAL_EVENTS_FILENAME] = file_digest(
                canonical_path
            )

    host_log_digests = bucketize_host_logs(
        data_root,
        out_root,
        window_start=origin,
        stage_minutes=stage_minutes,
        max_stage=max_stage,
    )
    for stage_name, digests in host_log_digests.items():
        stage_digests.setdefault(stage_name, {}).update(digests)

    return BucketizeResult(
        agent_root=out_root,
        stage_count=max_stage + 1,
        stage_digests=stage_digests,
        window_start=origin,
        stage_minutes=stage_minutes,
        max_stage=max_stage,
    )


def _discover_bucketizable_files(data_root: Path) -> list[Path]:
    """Return relative NDJSON paths under synthetic source subtrees."""
    if not data_root.is_dir():
        return []
    discovered: list[Path] = []
    for subdir in BUCKETIZED_DATA_SUBDIRS:
        subtree = data_root / subdir
        if not subtree.is_dir():
            continue
        for path in sorted(subtree.rglob("*.ndjson")):
            discovered.append(path.relative_to(data_root))
    return discovered


def _load_ndjson_records(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            msg = f"Invalid NDJSON at {path}:{line_no}"
            raise ValueError(msg) from exc
        if not isinstance(payload, dict):
            msg = f"Expected JSON object at {path}:{line_no}"
            raise ValueError(msg)
        records.append(payload)
    return records


def _resolve_max_stage(
    events: list[CanonicalEvent],
    source_records: dict[Path, list[dict[str, Any]]],
    window_start: datetime,
    *,
    stage_minutes: int,
) -> int:
    max_stage = 0
    if events:
        max_stage = max(
            stage_of(event.ts, window_start, stage_minutes=stage_minutes) for event in events
        )
    for records in source_records.values():
        for record in records:
            ts = _record_ts(record)
            if ts is None:
                continue
            max_stage = max(max_stage, stage_of(ts, window_start, stage_minutes=stage_minutes))
    return max_stage


def _record_visible_in_agent_stage(
    record: dict[str, Any],
    rel_path: Path,
    *,
    agent_stage: int,
    window_start: datetime,
    stage_minutes: int,
) -> bool:
    ts = _record_ts(record)
    if ts is None:
        return False
    if stage_of(ts, window_start, stage_minutes=stage_minutes) > agent_stage:
        return False
    if rel_path == HELPDESK_TICKETS_REL:
        return _passes_helpdesk_min_stage_gate(record, agent_stage)
    return True


def _passes_helpdesk_min_stage_gate(record: dict[str, Any], agent_stage: int) -> bool:
    """Apply precomputed helpdesk gate from step 4 (do not recompute from latency)."""
    gate = record.get("min_stage_gate")
    if gate is None:
        return True
    return agent_stage >= int(gate)


def _record_ts(record: dict[str, Any]) -> str | None:
    ts = record.get("ts")
    if isinstance(ts, str) and ts.strip():
        return ts
    return None


def _annotate_stage_index(
    record: dict[str, Any],
    window_start: datetime,
    *,
    stage_minutes: int,
) -> dict[str, Any]:
    ts = _record_ts(record)
    if ts is None:
        return dict(record)
    annotated = dict(record)
    annotated["stage_index"] = stage_of(ts, window_start, stage_minutes=stage_minutes)
    return annotated


def _canonical_to_stage_dict(
    event: CanonicalEvent,
    window_start: datetime,
    *,
    stage_minutes: int,
) -> dict[str, Any]:
    payload = event.model_dump(mode="json")
    payload["stage_index"] = stage_of(event.ts, window_start, stage_minutes=stage_minutes)
    return payload


def _record_sort_key(record: dict[str, Any]) -> tuple[str, str]:
    ts = str(record.get("ts", ""))
    record_id = str(
        record.get(
            "record_id",
            record.get("ticket_id", record.get("alert_id", record.get("evidence_id", ""))),
        )
    )
    return ts, record_id


def _write_ndjson_records(path: Path, records: list[dict[str, Any]]) -> Path:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(record, sort_keys=True) for record in sorted(records, key=_record_sort_key)]
    payload = "\n".join(lines)
    if payload:
        payload += "\n"
    safe_write_text(path, payload, encoding="utf-8")
    return path


def linked_evidence_stage_indices(
    record: dict[str, Any],
    events_by_id: dict[str, CanonicalEvent],
    window_start: datetime,
    *,
    stage_minutes: int = DEFAULT_STAGE_MINUTES,
) -> list[int]:
    """Return stage indices for linked canonical evidence (validate.py helper)."""
    metadata = record.get("__grader_metadata")
    if not isinstance(metadata, dict):
        return []
    linked = metadata.get("linked_evidence_ids")
    if not isinstance(linked, list):
        return []
    stages: list[int] = []
    for evidence_id in linked:
        event = events_by_id.get(str(evidence_id))
        if event is None:
            continue
        stages.append(stage_of(event.ts, window_start, stage_minutes=stage_minutes))
    return stages
