"""Cyber Threat Intelligence feed source with relevant IOCs and trap noise."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from socbench.capture.hashing import stable_seed
from socbench.capture.models import CanonicalEvent
from socbench.sources.common import (
    apply_latency,
    build_llm_cache,
    grader_metadata,
    pre_scenario_ts,
    summarize_result,
    write_source_records,
)
from socbench.sources.latency_budget import (
    CTI_RELEVANT_MAX_LATENCY_MS,
    CTI_RELEVANT_MIN_LATENCY_MS,
)
from socbench.sources.models import SourceBuildConfig, SourceBuildResult, SourceRecord
from socbench.sources.text import render_template_text
from socbench.truth.common import is_exfil_connection_event, is_external_ip

CTI_DIR = "cti"
TRAP_FEED_COUNT = 3
TRAP_IOC_PER_FEED = 12
RELEVANT_FEED_NAME = "incident_correlation.ndjson"


def build_cti_source(
    events: list[CanonicalEvent],
    data_root: Path,
    config: SourceBuildConfig,
) -> SourceBuildResult:
    """Write relevant CTI IOC rows plus deterministic trap feeds."""
    llm_cache = build_llm_cache(config)
    relevant_records = _build_relevant_records(events, config, llm_cache)
    trap_records = _build_trap_records(events, config)

    files: list[Path] = []
    cti_root = data_root / CTI_DIR / "feeds"
    if relevant_records:
        relevant_path = cti_root / RELEVANT_FEED_NAME
        write_source_records(relevant_path, relevant_records)
        files.append(relevant_path)

    for feed_index in range(TRAP_FEED_COUNT):
        feed_name = f"trap_noise_{feed_index:02d}.ndjson"
        feed_records = trap_records[
            feed_index * TRAP_IOC_PER_FEED : (feed_index + 1) * TRAP_IOC_PER_FEED
        ]
        feed_path = cti_root / feed_name
        write_source_records(feed_path, feed_records)
        files.append(feed_path)

    all_records = relevant_records + trap_records
    return summarize_result("cti", files, all_records)


def _build_relevant_records(
    events: list[CanonicalEvent],
    config: SourceBuildConfig,
    llm_cache: Any,
) -> list[SourceRecord]:
    records: list[SourceRecord] = []
    seen_indicators: set[str] = set()

    for event in events:
        indicators = _extract_indicators(event)
        if not indicators:
            continue
        for indicator_type, indicator in indicators:
            key = f"{indicator_type}:{indicator}"
            if key in seen_indicators:
                continue
            seen_indicators.add(key)
            latency_ms = _cti_latency_ms(config.seed, event.evidence_id, indicator)
            text = render_template_text(
                "cti_ioc_v1",
                seed=config.seed,
                linked_evidence_ids=[event.evidence_id],
                slots={
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                    "host": event.host,
                },
                llm_enabled=config.llm_enabled,
                llm_cache=llm_cache,
            )
            records.append(
                SourceRecord(
                    payload={
                        "record_id": f"cti-{event.evidence_id}-{indicator_type}",
                        "ts": apply_latency(event.ts, latency_ms),
                        "feed": "incident_correlation",
                        "indicator_type": indicator_type,
                        "indicator": indicator,
                        "confidence": "high",
                        "summary": text,
                    },
                    grader_metadata=grader_metadata(
                        linked_evidence_ids=[event.evidence_id],
                        latency_applied_ms=latency_ms,
                        template_id="cti_ioc_v1",
                    ),
                )
            )
    return records


def _extract_indicators(event: CanonicalEvent) -> list[tuple[str, str]]:
    indicators: list[tuple[str, str]] = []
    fields = event.fields

    dst_ip = fields.get("dst_ip")
    if isinstance(dst_ip, str) and is_external_ip(dst_ip):
        indicators.append(("ipv4", dst_ip))

    source_ip = fields.get("source_ip")
    if isinstance(source_ip, str) and is_external_ip(source_ip):
        indicators.append(("ipv4", source_ip))

    if event.kind == "process":
        process_name = str(fields.get("process_name", ""))
        if "darkside" in process_name.lower():
            indicators.append(("malware_family", "DarkSide"))
        command_line = str(fields.get("command_line", ""))
        if "0x733100" in command_line:
            indicators.append(("campaign_tag", "0x733100"))

    if is_exfil_connection_event(event):
        service = str(fields.get("service", "")).lower()
        if service:
            indicators.append(("protocol", service))

    return indicators


def _build_trap_records(
    events: list[CanonicalEvent],
    config: SourceBuildConfig,
) -> list[SourceRecord]:
    from random import Random

    rng = Random(stable_seed(f"cti_trap:{config.seed}"))
    records: list[SourceRecord] = []
    total = TRAP_FEED_COUNT * TRAP_IOC_PER_FEED
    for index in range(total):
        indicator_type = rng.choice(["ipv4", "domain", "sha256", "md5"])
        indicator = _random_trap_indicator(rng, indicator_type)
        records.append(
            SourceRecord(
                payload={
                    "record_id": f"cti-trap-{index:03d}",
                    "ts": pre_scenario_ts(events, config, salt="cti_trap", index=index),
                    "feed": f"trap_noise_{index // TRAP_IOC_PER_FEED:02d}",
                    "indicator_type": indicator_type,
                    "indicator": indicator,
                    "confidence": "low",
                    "summary": "Historical commodity malware IOC; no current enterprise relevance.",
                },
                grader_metadata=None,
            )
        )
    return records


def _random_trap_indicator(rng: Any, indicator_type: str) -> str:
    if indicator_type == "ipv4":
        return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    if indicator_type == "domain":
        return f"{rng.choice(['update', 'cdn', 'static', 'api'])}-{rng.randint(100, 999)}.example-trap.net"
    if indicator_type == "sha256":
        return rng.randbytes(32).hex()
    return rng.randbytes(16).hex()


def _cti_latency_ms(seed: int, evidence_id: str, indicator: str) -> int:
    from random import Random

    rng = Random(stable_seed(f"cti_latency:{seed}:{evidence_id}:{indicator}"))
    return rng.randint(CTI_RELEVANT_MIN_LATENCY_MS, CTI_RELEVANT_MAX_LATENCY_MS)
