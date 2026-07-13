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
from socbench.sources.latency_budget import (
    HELPDESK_LATENCY_JITTER_MS,
    HELPDESK_LATENCY_MIN_MS,
    HELPDESK_NEGATIVE_JITTER_MS,
)
from socbench.sources.models import SourceBuildConfig, SourceBuildResult, SourceRecord
from socbench.sources.text import render_template_text
from socbench.truth.common import is_ransomware_event, parse_ts, resolve_window_start, stage_of

HELPDESK_DIR = "helpdesk"
_HELPDESK_TEMPLATES = ("ransom_note_v1", "ransom_note_v2", "ransom_note_v3")
_INTERACTIVE_HOST_PREFIXES = ("WKS", "OFFICE", "MUSIC", "WS-")


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

        reporters = _derive_helpdesk_reporters(event, events)
        template_id = _helpdesk_template_id(event.host, config.seed)
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


def _derive_helpdesk_reporters(
    encrypt_event: CanonicalEvent,
    events: list[CanonicalEvent],
) -> list[tuple[str, str]]:
    """Derive ticket reporters from canonical events that reference the affected host."""
    affected_host = encrypt_event.host
    encrypt_time = parse_ts(encrypt_event.ts)
    prior_events = [event for event in events if parse_ts(event.ts) <= encrypt_time]
    ip_to_host = _internal_ip_to_host(prior_events)
    reporters: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(username: str, workstation: str) -> None:
        user = _normalize_username(username)
        ws = workstation or affected_host
        pair = (user, ws)
        if user and pair not in seen:
            seen.add(pair)
            reporters.append(pair)

    for event in prior_events:
        if event.kind == "explicit_credentials":
            target = event.fields.get("target_server")
            if target != affected_host:
                continue
            username = str(event.fields.get("target_username", event.actor))
            workstation = _workstation_for_actor(prior_events, event.actor, ip_to_host)
            add(username, workstation)

    for event in prior_events:
        if event.kind != "logon" or event.host != affected_host:
            continue
        source_ip = event.fields.get("source_ip")
        workstation = affected_host
        if isinstance(source_ip, str):
            workstation = ip_to_host.get(
                source_ip,
                _workstation_from_source_ip(prior_events, source_ip),
            )
        add(event.actor, workstation)

    if not reporters:
        add(encrypt_event.actor, affected_host)

    reporters.sort()
    return reporters[:5]


def _helpdesk_template_id(host: str, seed: int) -> str:
    index = stable_seed(f"helpdesk_template:{seed}:{host}") % len(_HELPDESK_TEMPLATES)
    return _HELPDESK_TEMPLATES[index]


def _normalize_username(username: str) -> str:
    if "\\" in username:
        return username.split("\\", maxsplit=1)[1]
    return username


def _internal_ip_to_host(events: list[CanonicalEvent]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for event in events:
        source_ip = event.fields.get("source_ip")
        if isinstance(source_ip, str) and source_ip.startswith("10."):
            mapping.setdefault(source_ip, event.host)
    return mapping


def _workstation_for_actor(
    events: list[CanonicalEvent],
    actor: str,
    ip_to_host: dict[str, str],
) -> str:
    del ip_to_host
    for event in events:
        if event.actor != actor:
            continue
        if _looks_like_workstation(event.host):
            return event.host
    for event in events:
        if event.actor == actor:
            return event.host
    return "UNKNOWN-WS"


def _workstation_from_source_ip(events: list[CanonicalEvent], source_ip: str) -> str:
    for event in events:
        if event.fields.get("source_ip") != source_ip:
            continue
        if event.kind in {"rdp_session", "logon", "connection", "ssh_session"}:
            return event.host
    return f"WS-{source_ip.rsplit('.', maxsplit=1)[-1]}"


def _looks_like_workstation(host: str) -> bool:
    return host.startswith(_INTERACTIVE_HOST_PREFIXES) or "OPS" in host


def _ticket_latency_ms(seed: int, evidence_id: str, ticket_index: int, *, base_ms: int) -> int:
    from random import Random

    rng = Random(stable_seed(f"helpdesk_latency:{seed}:{evidence_id}:{ticket_index}"))
    jitter = rng.randint(-HELPDESK_NEGATIVE_JITTER_MS, HELPDESK_LATENCY_JITTER_MS)
    return max(HELPDESK_LATENCY_MIN_MS, base_ms + jitter)


def _ticket_id(seed: int, evidence_id: str, ticket_index: int) -> str:
    from random import Random

    rng = Random(stable_seed(f"helpdesk_ticket:{seed}:{evidence_id}:{ticket_index}"))
    return f"HD-{rng.randint(9000, 9999)}"
