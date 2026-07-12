"""Helpdesk ticket source with late user reports and stage gating."""

from __future__ import annotations

from pathlib import Path

from socbench.capture.hashing import stable_seed
from socbench.capture.models import CanonicalEvent
from socbench.sources.common import (
    apply_latency,
    build_llm_cache,
    grader_metadata,
    resolve_helpdesk_min_stage,
    summarize_result,
    write_source_records,
)
from socbench.sources.models import SourceBuildConfig, SourceBuildResult, SourceRecord
from socbench.sources.text import render_template_text
from socbench.truth.common import is_ransomware_event, resolve_window_start, stage_of

HELPDESK_DIR = "helpdesk"

# Colonial-style workstation users mapped to affected file-server hosts.
_HOST_REPORTERS: dict[str, list[tuple[str, str]]] = {
    "FS-01": [
        ("j.walsh", "WKS-01"),
        ("m.chen", "WKS-02"),
        ("r.patel", "WKS-03"),
    ],
    "FS-02": [
        ("s.kim", "WKS-04"),
        ("d.nguyen", "WKS-04"),
    ],
}

_TEMPLATE_BY_HOST: dict[str, str] = {
    "FS-01": "ransom_note_v3",
    "FS-02": "ransom_note_v2",
}


def build_helpdesk_source(
    events: list[CanonicalEvent],
    data_root: Path,
    config: SourceBuildConfig,
) -> SourceBuildResult:
    """Write late helpdesk tickets gated to the second half of the scenario."""
    llm_cache = build_llm_cache(config)
    min_stage = resolve_helpdesk_min_stage(events, config)
    origin = resolve_window_start(events, config.window_start) if events else None
    records: list[SourceRecord] = []

    encrypt_events = [event for event in events if is_ransomware_event(event)]
    for event in encrypt_events:
        if origin is not None:
            event_stage = stage_of(event.ts, origin, stage_minutes=config.stage_minutes)
            if event_stage < min_stage:
                continue

        reporters = _HOST_REPORTERS.get(event.host, [("user", event.host)])
        template_id = _TEMPLATE_BY_HOST.get(event.host, "ransom_note_v1")
        for ticket_index, (username, workstation) in enumerate(reporters):
            latency_ms = _ticket_latency_ms(
                config.seed,
                event.evidence_id,
                ticket_index,
                base_ms=config.helpdesk_base_latency_ms,
            )
            ticket_ts = apply_latency(event.ts, latency_ms)
            text = render_template_text(
                template_id,
                seed=config.seed,
                linked_evidence_ids=[event.evidence_id],
                slots={"user": username, "host": workstation},
                llm_enabled=config.llm_enabled,
                llm_cache=llm_cache,
            )
            ticket_id = _ticket_id(config.seed, event.evidence_id, ticket_index)
            records.append(
                SourceRecord(
                    payload={
                        "ticket_id": ticket_id,
                        "ts": ticket_ts,
                        "user": username,
                        "host": workstation,
                        "category": "incident",
                        "priority": "high",
                        "text": text,
                        "related_host": event.host,
                        "min_stage_gate": min_stage,
                    },
                    grader_metadata=grader_metadata(
                        linked_evidence_ids=[event.evidence_id],
                        latency_applied_ms=latency_ms,
                        template_id=template_id,
                    ),
                )
            )

    files: list[Path] = []
    if records:
        out_path = data_root / HELPDESK_DIR / "tickets.ndjson"
        write_source_records(out_path, records)
        files.append(out_path)

    return summarize_result("helpdesk", files, records)


def _ticket_latency_ms(seed: int, evidence_id: str, ticket_index: int, *, base_ms: int) -> int:
    from random import Random

    rng = Random(stable_seed(f"helpdesk_latency:{seed}:{evidence_id}:{ticket_index}"))
    jitter = rng.randint(-300_000, 900_000)
    return max(60_000, base_ms + jitter)


def _ticket_id(seed: int, evidence_id: str, ticket_index: int) -> str:
    from random import Random

    rng = Random(stable_seed(f"helpdesk_ticket:{seed}:{evidence_id}:{ticket_index}"))
    return f"HD-{rng.randint(9000, 9999)}"
