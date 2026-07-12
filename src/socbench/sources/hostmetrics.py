"""Host time-series metrics with encryption/exfil spikes and partial coverage (DP4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from socbench.capture.hashing import stable_seed
from socbench.capture.models import CanonicalEvent
from socbench.sources.common import (
    collect_hosts,
    grader_metadata,
    summarize_result,
    write_source_records,
)
from socbench.sources.models import SourceBuildConfig, SourceBuildResult, SourceRecord
from socbench.truth.common import (
    connection_bytes,
    is_exfil_connection_event,
    is_ransomware_event,
    parse_ts,
    resolve_window_start,
)

HOSTMETRICS_DIR = "hostmetrics"
SAMPLE_INTERVAL_MINUTES = 5

# DP4: deliberate telemetry gaps — documented excluded hosts (no hostmetrics files).
HOSTMETRICS_EXCLUDED_HOSTS: frozenset[str] = frozenset(
    {
        "OT-HMI-01",  # OT segment without endpoint monitoring agent
        "DC-01",  # domain controller excluded from capacity metrics rollout
    }
)
HOSTMETRICS_EXCLUSION_REASONS: dict[str, str] = {
    "OT-HMI-01": "OT HMI lacks enterprise metrics agent (segment isolation).",
    "DC-01": "DC excluded from hostmetrics pilot deployment.",
}


def build_hostmetrics_source(
    events: list[CanonicalEvent],
    data_root: Path,
    config: SourceBuildConfig,
) -> SourceBuildResult:
    """Write per-host CPU/mem/IO/net samples with spikes aligned to impact/exfil events."""
    if not events:
        return summarize_result("hostmetrics", [], [])

    origin = resolve_window_start(events, config.window_start)
    end_time = max(parse_ts(event.ts) for event in events) + timedelta(minutes=15)
    spike_windows = _build_spike_windows(events)

    files: list[Path] = []
    all_records: list[SourceRecord] = []
    for host in collect_hosts(events):
        if host in HOSTMETRICS_EXCLUDED_HOSTS:
            continue
        host_records = _host_timeseries(
            host=host,
            origin=origin,
            end_time=end_time,
            spike_windows=spike_windows.get(host, []),
            seed=config.seed,
        )
        if not host_records:
            continue
        out_path = data_root / HOSTMETRICS_DIR / f"{host}.ndjson"
        write_source_records(out_path, host_records)
        files.append(out_path)
        all_records.extend(host_records)

    return summarize_result("hostmetrics", files, all_records)


def hostmetrics_coverage_doc() -> dict[str, object]:
    """Return documented DP4 hostmetrics exclusion metadata."""
    return {
        "excluded_hosts": sorted(HOSTMETRICS_EXCLUDED_HOSTS),
        "reasons": dict(HOSTMETRICS_EXCLUSION_REASONS),
    }


def _build_spike_windows(events: list[CanonicalEvent]) -> dict[str, list[dict[str, object]]]:
    windows: dict[str, list[dict[str, object]]] = {}
    for event in events:
        if not (is_ransomware_event(event) or is_exfil_connection_event(event)):
            continue
        start = parse_ts(event.ts)
        end = start + timedelta(minutes=10)
        spike_type = "encryption" if is_ransomware_event(event) else "exfil"
        windows.setdefault(event.host, []).append(
            {
                "start": start,
                "end": end,
                "spike_type": spike_type,
                "evidence_id": event.evidence_id,
                "weight": 1.0
                if spike_type == "encryption"
                else min(connection_bytes(event) / 500_000_000, 1.0),
            }
        )
    return windows


def _host_timeseries(
    *,
    host: str,
    origin: datetime,
    end_time: datetime,
    spike_windows: list[dict[str, object]],
    seed: int,
) -> list[SourceRecord]:
    from random import Random

    rng = Random(stable_seed(f"hostmetrics:{seed}:{host}"))
    records: list[SourceRecord] = []
    sample_time = origin
    sample_index = 0
    while sample_time <= end_time:
        base_cpu = rng.uniform(8.0, 25.0)
        base_mem = rng.uniform(35.0, 55.0)
        base_io = rng.uniform(5.0, 20.0)
        base_net = rng.uniform(1.0, 8.0)

        linked_ids: list[str] = []
        spike_multiplier = 1.0
        spike_type = "baseline"
        for window in spike_windows:
            start = window["start"]
            end = window["end"]
            assert isinstance(start, datetime)
            assert isinstance(end, datetime)
            if start <= sample_time <= end:
                weight = float(window.get("weight", 1.0))
                spike_multiplier = max(spike_multiplier, 1.0 + (2.5 * weight))
                spike_type = str(window["spike_type"])
                evidence_id = str(window["evidence_id"])
                if evidence_id not in linked_ids:
                    linked_ids.append(evidence_id)

        cpu = min(99.0, base_cpu * spike_multiplier)
        mem = min(99.0, base_mem * (1.0 + 0.3 * (spike_multiplier - 1.0)))
        io_mbps = base_io * spike_multiplier
        net_mbps = base_net * spike_multiplier

        metadata = None
        if linked_ids:
            metadata = grader_metadata(
                linked_evidence_ids=linked_ids,
                latency_applied_ms=0,
                template_id="hostmetrics_spike_v1",
            )

        ts_text = sample_time.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        records.append(
            SourceRecord(
                payload={
                    "record_id": f"hm-{host}-{sample_index:04d}",
                    "ts": ts_text,
                    "host": host,
                    "cpu_pct": round(cpu, 2),
                    "mem_pct": round(mem, 2),
                    "disk_io_mbps": round(io_mbps, 2),
                    "net_mbps": round(net_mbps, 2),
                    "spike_type": spike_type,
                },
                grader_metadata=metadata,
            )
        )
        sample_time += timedelta(minutes=SAMPLE_INTERVAL_MINUTES)
        sample_index += 1
    return records
