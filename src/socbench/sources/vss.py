"""Volume Shadow Copy backup log and process telemetry duplication."""

from __future__ import annotations

from pathlib import Path

from socbench.capture.hashing import stable_seed
from socbench.capture.models import CanonicalEvent
from socbench.sources.common import (
    apply_latency,
    build_llm_cache,
    event_summary_for_slots,
    grader_metadata,
    summarize_result,
    write_source_records,
)
from socbench.sources.models import SourceBuildConfig, SourceBuildResult, SourceRecord
from socbench.sources.text import render_template_text
from socbench.truth.common import is_vss_delete_event

VSS_LOG_DIR = "vss"
PROCESS_TELEMETRY_DIR = "process_telemetry"


def build_vss_source(
    events: list[CanonicalEvent],
    data_root: Path,
    config: SourceBuildConfig,
) -> SourceBuildResult:
    """Write VSS backup logs and duplicate vssadmin rows into process telemetry."""
    llm_cache = build_llm_cache(config)
    vss_records: list[SourceRecord] = []
    process_records: list[SourceRecord] = []

    for event in events:
        if not is_vss_delete_event(event):
            continue
        fields = event.fields
        latency_ms = _vss_latency_ms(config.seed, event.evidence_id)
        observed_ts = apply_latency(event.ts, latency_ms)
        slots = event_summary_for_slots(event)
        message = render_template_text(
            "vss_delete_shadows_v1",
            seed=config.seed,
            linked_evidence_ids=[event.evidence_id],
            slots=slots,
            llm_enabled=config.llm_enabled,
            llm_cache=llm_cache,
        )
        metadata = grader_metadata(
            linked_evidence_ids=[event.evidence_id],
            latency_applied_ms=latency_ms,
            template_id="vss_delete_shadows_v1",
        )
        vss_records.append(
            SourceRecord(
                payload={
                    "record_id": f"vss-{event.evidence_id}",
                    "ts": observed_ts,
                    "host": event.host,
                    "operation": "delete_shadows",
                    "provider": "Microsoft Software Shadow Copy Provider",
                    "process_name": fields.get("process_name"),
                    "pid": fields.get("pid"),
                    "command_line": fields.get("command_line"),
                    "message": message,
                },
                grader_metadata=metadata,
            )
        )
        process_records.append(
            SourceRecord(
                payload={
                    "record_id": f"proc-vss-{event.evidence_id}",
                    "ts": observed_ts,
                    "host": event.host,
                    "source": "process_telemetry",
                    "event_type": "process_create",
                    "process_name": fields.get("process_name"),
                    "pid": fields.get("pid"),
                    "ppid": fields.get("ppid"),
                    "command_line": fields.get("command_line"),
                    "parent_image": fields.get("parent_image"),
                },
                grader_metadata=metadata,
            )
        )

    files: list[Path] = []
    if vss_records:
        host = vss_records[0].payload["host"]
        vss_path = data_root / VSS_LOG_DIR / str(host) / "shadow_ops.ndjson"
        write_source_records(vss_path, vss_records)
        files.append(vss_path)
        proc_path = data_root / PROCESS_TELEMETRY_DIR / "vss_duplicates.ndjson"
        write_source_records(proc_path, process_records)
        files.append(proc_path)

    all_records = vss_records + process_records
    return summarize_result("vss", files, all_records)


def _vss_latency_ms(seed: int, evidence_id: str) -> int:
    from random import Random

    rng = Random(stable_seed(f"vss_latency:{seed}:{evidence_id}"))
    return rng.randint(30_000, 120_000)
