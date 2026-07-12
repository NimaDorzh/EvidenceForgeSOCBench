"""Rule-based SIEM alert layer with latency, false positives, and false negatives."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
from socbench.truth.common import (
    is_exfil_connection_event,
    is_psexec_helper_service,
    is_psexec_launcher_event,
    is_ransomware_event,
    is_vss_delete_event,
)

SIEM_DIR = "siem"
ALERTS_FILENAME = "alerts.ndjson"
XDR_FILENAME = "xdr_anomalies.ndjson"


@dataclass(frozen=True, slots=True)
class SiemRule:
    """One SIEM correlation rule with DP4 latency and miss rate."""

    rule_id: str
    severity: str
    summary: str
    template_id: str
    latency_ms: int
    fn_rate: float
    matcher: Callable[[CanonicalEvent], bool]


def build_siem_source(
    events: list[CanonicalEvent],
    data_root: Path,
    config: SourceBuildConfig,
) -> SourceBuildResult:
    """Write SIEM alerts and optional XDR anomalies from canonical events."""
    llm_cache = build_llm_cache(config)
    rules = _default_rules()
    alert_records: list[SourceRecord] = []
    xdr_records: list[SourceRecord] = []

    for event in events:
        for rule in rules:
            if not rule.matcher(event):
                continue
            if _should_suppress_alert(config.seed, event.evidence_id, rule.rule_id, rule.fn_rate):
                continue
            slots = event_summary_for_slots(event)
            slots["rule_id"] = rule.rule_id
            slots["severity"] = rule.severity
            slots["summary"] = rule.summary
            text = render_template_text(
                rule.template_id,
                seed=config.seed,
                linked_evidence_ids=[event.evidence_id],
                slots=slots,
                llm_enabled=config.llm_enabled,
                llm_cache=llm_cache,
            )
            alert_records.append(
                SourceRecord(
                    payload={
                        "alert_id": f"SIEM-{rule.rule_id}-{event.evidence_id}",
                        "ts": apply_latency(event.ts, rule.latency_ms),
                        "rule_id": rule.rule_id,
                        "severity": rule.severity,
                        "host": event.host,
                        "correlated_hosts": _correlated_hosts(event),
                        "summary": text,
                        "source_formats": list(event.observed_by),
                    },
                    grader_metadata=grader_metadata(
                        linked_evidence_ids=[event.evidence_id],
                        latency_applied_ms=rule.latency_ms,
                        template_id=rule.template_id,
                    ),
                )
            )

        if _is_xdr_candidate(event):
            xdr_records.extend(_xdr_rows_for_event(event, config, llm_cache))

    fp_records = _false_positive_alerts(events, config, llm_cache)
    alert_records.extend(fp_records)

    files: list[Path] = []
    siem_root = data_root / SIEM_DIR
    if alert_records:
        alerts_path = siem_root / ALERTS_FILENAME
        write_source_records(alerts_path, alert_records)
        files.append(alerts_path)
    if xdr_records:
        xdr_path = siem_root / XDR_FILENAME
        write_source_records(xdr_path, xdr_records)
        files.append(xdr_path)

    all_records = alert_records + xdr_records
    return summarize_result("siem", files, all_records)


def _default_rules() -> list[SiemRule]:
    return [
        SiemRule(
            rule_id="CORR-001",
            severity="medium",
            summary="Suspicious remote service installation",
            template_id="siem_alert_v1",
            latency_ms=120_000,
            fn_rate=0.0,
            matcher=lambda event: is_psexec_helper_service(event),
        ),
        SiemRule(
            rule_id="CORR-002",
            severity="high",
            summary="Remote execution tool launch detected",
            template_id="siem_alert_v1",
            latency_ms=90_000,
            fn_rate=0.0,
            matcher=lambda event: is_psexec_launcher_event(event),
        ),
        SiemRule(
            rule_id="CORR-003",
            severity="high",
            summary="Large outbound transfer to external destination",
            template_id="siem_alert_v1",
            latency_ms=300_000,
            fn_rate=0.0,
            matcher=is_exfil_connection_event,
        ),
        SiemRule(
            rule_id="CORR-004",
            severity="critical",
            summary="Shadow copy deletion command observed",
            template_id="siem_alert_v1",
            latency_ms=60_000,
            fn_rate=0.0,
            matcher=is_vss_delete_event,
        ),
        SiemRule(
            rule_id="CORR-005",
            severity="critical",
            summary="Mass encryption activity detected",
            template_id="siem_alert_v1",
            latency_ms=45_000,
            fn_rate=0.0,
            matcher=is_ransomware_event,
        ),
        SiemRule(
            rule_id="CORR-006",
            severity="high",
            summary="Suspicious remote thread creation",
            template_id="siem_alert_v1",
            latency_ms=180_000,
            fn_rate=1.0,
            matcher=lambda event: event.kind == "create_remote_thread",
        ),
        SiemRule(
            rule_id="CORR-007",
            severity="medium",
            summary="Interactive remote session from internal pivot",
            template_id="siem_alert_v1",
            latency_ms=240_000,
            fn_rate=0.5,
            matcher=lambda event: event.kind == "rdp_session",
        ),
    ]


def _should_suppress_alert(seed: int, evidence_id: str, rule_id: str, fn_rate: float) -> bool:
    if fn_rate <= 0.0:
        return False
    from random import Random

    rng = Random(stable_seed(f"siem_fn:{seed}:{evidence_id}:{rule_id}"))
    return rng.random() < fn_rate


def _correlated_hosts(event: CanonicalEvent) -> list[str]:
    hosts = {event.host}
    for field_name in ("target_server",):
        value = event.fields.get(field_name)
        if isinstance(value, str) and value:
            hosts.add(value)
    dst_ip = event.fields.get("dst_ip")
    if isinstance(dst_ip, str) and dst_ip.startswith("10."):
        hosts.add(dst_ip)
    return sorted(hosts)


def _is_xdr_candidate(event: CanonicalEvent) -> bool:
    return event.kind in {"process", "create_remote_thread"} and "ecar" in event.observed_by


def _xdr_rows_for_event(
    event: CanonicalEvent,
    config: SourceBuildConfig,
    llm_cache: Any,
) -> list[SourceRecord]:
    from random import Random

    rng = Random(stable_seed(f"xdr:{config.seed}:{event.evidence_id}"))
    anomaly_type = (
        "process_injection" if event.kind == "create_remote_thread" else "suspicious_process"
    )
    score = round(rng.uniform(72.0, 98.0), 1)
    text = render_template_text(
        "xdr_anomaly_v1",
        seed=config.seed,
        linked_evidence_ids=[event.evidence_id],
        slots={"host": event.host, "anomaly_type": anomaly_type, "score": score},
        llm_enabled=config.llm_enabled,
        llm_cache=llm_cache,
    )
    return [
        SourceRecord(
            payload={
                "record_id": f"xdr-{event.evidence_id}",
                "ts": apply_latency(event.ts, rng.randint(30_000, 150_000)),
                "host": event.host,
                "anomaly_type": anomaly_type,
                "score": score,
                "summary": text,
            },
            grader_metadata=grader_metadata(
                linked_evidence_ids=[event.evidence_id],
                latency_applied_ms=0,
                template_id="xdr_anomaly_v1",
            ),
        )
    ]


def _false_positive_alerts(
    events: list[CanonicalEvent],
    config: SourceBuildConfig,
    llm_cache: Any,
) -> list[SourceRecord]:
    hosts = sorted({event.host for event in events})
    fp_count = 8
    records: list[SourceRecord] = []
    for index in range(fp_count):
        host = hosts[index % len(hosts)] if hosts else "WKS-01"
        rule_id = f"FP-{100 + index}"
        text = render_template_text(
            "siem_alert_v1",
            seed=config.seed,
            linked_evidence_ids=[],
            slots={
                "rule_id": rule_id,
                "severity": "low",
                "host": host,
                "summary": "Benign admin activity matched legacy threshold",
            },
            llm_enabled=config.llm_enabled,
            llm_cache=llm_cache,
        )
        records.append(
            SourceRecord(
                payload={
                    "alert_id": f"SIEM-{rule_id}-noise-{index}",
                    "ts": "2024-06-03T08:30:00Z",
                    "rule_id": rule_id,
                    "severity": "low",
                    "host": host,
                    "correlated_hosts": [host],
                    "summary": text,
                    "false_positive": True,
                },
                grader_metadata=None,
            )
        )
    return records
