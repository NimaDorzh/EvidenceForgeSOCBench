"""Tests for SOC-bench synthetic sources (step 4)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from socbench.capture.models import CanonicalEvent
from socbench.sources import build_sources_from_file
from socbench.sources.common import file_digest, load_events
from socbench.sources.cti import build_cti_source
from socbench.sources.errors import UncachedLlmCallError
from socbench.sources.helpdesk import build_helpdesk_source
from socbench.sources.hostmetrics import (
    HOSTMETRICS_EXCLUDED_HOSTS,
    build_hostmetrics_source,
    hostmetrics_coverage_doc,
)
from socbench.sources.models import SourceBuildConfig
from socbench.sources.siem import build_siem_source
from socbench.sources.text import LlmTextCache, render_template_text
from socbench.sources.vss import build_vss_source
from socbench.truth.common import index_by_evidence_id, is_vss_delete_event, parse_ts, resolve_window_start

REPO_ROOT = Path(__file__).resolve().parents[2]
COLONIAL_EVENTS = (
    REPO_ROOT / "scenarios" / "colonial-pipeline" / "grader" / "canonical_events.ndjson"
)
COLONIAL_WINDOW_START = "2024-06-03T08:00:00Z"


def _colonial_config(**overrides: object) -> SourceBuildConfig:
    base = {
        "seed": 42,
        "window_start": COLONIAL_WINDOW_START,
        "stage_minutes": 30,
    }
    base.update(overrides)
    return SourceBuildConfig.model_validate(base)


def _load_ndjson(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _linked_ids(record: dict[str, object]) -> list[str]:
    metadata = record.get("__grader_metadata")
    if not isinstance(metadata, dict):
        return []
    linked = metadata.get("linked_evidence_ids")
    if not isinstance(linked, list):
        return []
    return [str(item) for item in linked]


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_vss_source_links_canonical_and_duplicates_process_telemetry(tmp_path: Path) -> None:
    events = load_events(COLONIAL_EVENTS)
    data_root = tmp_path / "data"
    result = build_vss_source(events, data_root, _colonial_config())

    assert result.attack_linked_count >= 1
    vss_path = data_root / "vss" / "FS-01" / "shadow_ops.ndjson"
    proc_path = data_root / "process_telemetry" / "vss_duplicates.ndjson"
    assert vss_path.is_file()
    assert proc_path.is_file()

    vss_rows = _load_ndjson(vss_path)
    proc_rows = _load_ndjson(proc_path)
    assert len(vss_rows) == len(proc_rows) == 1
    assert vss_rows[0]["operation"] == "delete_shadows"
    assert "vssadmin" in str(proc_rows[0]["command_line"]).lower()

    events_by_id = index_by_evidence_id(events)
    for row in vss_rows + proc_rows:
        linked = _linked_ids(row)
        assert len(linked) == 1
        assert linked[0] in events_by_id
        assert is_vss_delete_event(events_by_id[linked[0]])


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_helpdesk_tickets_are_late_and_stage_gated(tmp_path: Path) -> None:
    events = load_events(COLONIAL_EVENTS)
    data_root = tmp_path / "data"
    config = _colonial_config(helpdesk_min_stage=4)
    result = build_helpdesk_source(events, data_root, config)

    assert result.record_count >= 1
    tickets_path = data_root / "helpdesk" / "tickets.ndjson"
    assert tickets_path.is_file()
    rows = _load_ndjson(tickets_path)
    encrypt_ids = {
        event.evidence_id
        for event in events
        if "encrypt" in str(event.fields.get("command_line", "")).lower()
    }
    for row in rows:
        assert row["min_stage_gate"] == 4
        linked = _linked_ids(row)
        assert linked and linked[0] in encrypt_ids
        metadata = row["__grader_metadata"]
        assert isinstance(metadata, dict)
        assert metadata["latency_applied_ms"] >= 60_000


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_cti_trap_feeds_have_no_attack_evidence_ids(tmp_path: Path) -> None:
    events = load_events(COLONIAL_EVENTS)
    data_root = tmp_path / "data"
    result = build_cti_source(events, data_root, _colonial_config())

    assert result.record_count > 20
    relevant = _load_ndjson(data_root / "cti" / "feeds" / "incident_correlation.ndjson")
    trap_rows: list[dict[str, object]] = []
    for feed_path in sorted((data_root / "cti" / "feeds").glob("trap_noise_*.ndjson")):
        trap_rows.extend(_load_ndjson(feed_path))

    assert relevant
    assert len(trap_rows) >= 30
    for row in relevant:
        assert _linked_ids(row)
    for row in trap_rows:
        assert not _linked_ids(row)


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_cti_trap_timestamps_are_pre_scenario_and_deterministic(tmp_path: Path) -> None:
    events = load_events(COLONIAL_EVENTS)
    config = _colonial_config()
    origin = resolve_window_start(events, config.window_start)

    first_root = tmp_path / "run1" / "data"
    second_root = tmp_path / "run2" / "data"
    build_cti_source(events, first_root, config)
    build_cti_source(events, second_root, config)

    def _trap_rows(root: Path) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for feed_path in sorted((root / "cti" / "feeds").glob("trap_noise_*.ndjson")):
            rows.extend(_load_ndjson(feed_path))
        return rows

    first_traps = _trap_rows(first_root)
    second_traps = _trap_rows(second_root)
    assert first_traps
    assert [row["ts"] for row in first_traps] == [row["ts"] for row in second_traps]

    for row in first_traps:
        ts = parse_ts(str(row["ts"]))
        assert ts < origin, "trap IOC timestamps must predate the scenario window"


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_cti_relevant_timestamps_respect_forward_latency_budget(tmp_path: Path) -> None:
    from datetime import timedelta

    from socbench.sources.latency_budget import CTI_RELEVANT_MAX_LATENCY_MS

    events = load_events(COLONIAL_EVENTS)
    config = _colonial_config()
    data_root = tmp_path / "data"
    build_cti_source(events, data_root, config)

    origin = resolve_window_start(events, config.window_start)
    last_event = max(events, key=lambda event: parse_ts(event.ts))
    horizon = parse_ts(last_event.ts) + timedelta(milliseconds=CTI_RELEVANT_MAX_LATENCY_MS)
    relevant = _load_ndjson(data_root / "cti" / "feeds" / "incident_correlation.ndjson")
    assert relevant
    for row in relevant:
        ts = parse_ts(str(row["ts"]))
        assert origin <= ts <= horizon


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_hostmetrics_excluded_hosts_documented_and_omitted(tmp_path: Path) -> None:
    events = load_events(COLONIAL_EVENTS)
    data_root = tmp_path / "data"
    build_hostmetrics_source(events, data_root, _colonial_config())

    coverage = hostmetrics_coverage_doc()
    assert set(coverage["excluded_hosts"]) == set(HOSTMETRICS_EXCLUDED_HOSTS)
    assert "OT-HMI-01" in coverage["reasons"]

    metrics_dir = data_root / "hostmetrics"
    written_hosts = {path.stem for path in metrics_dir.glob("*.ndjson")}
    assert HOSTMETRICS_EXCLUDED_HOSTS.isdisjoint(written_hosts)

    fs_metrics = _load_ndjson(metrics_dir / "FS-01.ndjson")
    spike_rows = [row for row in fs_metrics if row.get("spike_type") == "encryption"]
    assert spike_rows
    assert any(_linked_ids(row) for row in spike_rows)


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_siem_latency_fp_fn_rules(tmp_path: Path) -> None:
    events = load_events(COLONIAL_EVENTS)
    data_root = tmp_path / "data"
    build_siem_source(events, data_root, _colonial_config())

    alerts = _load_ndjson(data_root / "siem" / "alerts.ndjson")
    fp_rows = [row for row in alerts if row.get("false_positive") is True]
    attack_rows = [row for row in alerts if not row.get("false_positive")]

    assert len(fp_rows) >= 5
    assert all(not _linked_ids(row) for row in fp_rows)
    assert attack_rows

    events_by_id = index_by_evidence_id(events)
    for row in attack_rows:
        linked = _linked_ids(row)
        assert linked
        assert linked[0] in events_by_id

    # FN rules: create_remote_thread and some rdp_session alerts suppressed deterministically.
    crt_ids = {event.evidence_id for event in events if event.kind == "create_remote_thread"}
    crt_alerts = [row for row in attack_rows if any(eid in crt_ids for eid in _linked_ids(row))]
    assert crt_alerts == []

    xdr_rows = _load_ndjson(data_root / "siem" / "xdr_anomalies.ndjson")
    assert xdr_rows


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_siem_false_positive_timestamps_stay_within_scenario_window(tmp_path: Path) -> None:
    events = load_events(COLONIAL_EVENTS)
    config = _colonial_config()
    data_root = tmp_path / "data"
    build_siem_source(events, data_root, config)

    origin = resolve_window_start(events, config.window_start)
    last_event = max(events, key=lambda event: parse_ts(event.ts))
    horizon = parse_ts(last_event.ts)
    alerts = _load_ndjson(data_root / "siem" / "alerts.ndjson")
    fp_rows = [row for row in alerts if row.get("false_positive") is True]
    assert fp_rows
    for row in fp_rows:
        ts = parse_ts(str(row["ts"]))
        assert origin <= ts <= horizon


def test_render_template_is_deterministic_without_llm() -> None:
    first = render_template_text(
        "ransom_note_v3",
        seed=42,
        linked_evidence_ids=["EVID-abc"],
        slots={"user": "j.smith", "host": "WKS-01"},
    )
    second = render_template_text(
        "ransom_note_v3",
        seed=42,
        linked_evidence_ids=["EVID-abc"],
        slots={"user": "j.smith", "host": "WKS-01"},
    )
    other_seed = render_template_text(
        "ransom_note_v3",
        seed=99,
        linked_evidence_ids=["EVID-abc"],
        slots={"user": "j.smith", "host": "WKS-01"},
    )
    assert first == second
    assert first != other_seed


def test_uncached_llm_call_is_blocked_when_llm_enabled_without_cache() -> None:
    """llm_enabled=True and no cache must raise UncachedLlmCallError (no template fallback)."""
    with pytest.raises(UncachedLlmCallError, match="Uncached LLM call blocked"):
        render_template_text(
            "ransom_note_v1",
            seed=42,
            linked_evidence_ids=["EVID-x"],
            slots={"user": "a", "host": "b"},
            llm_enabled=True,
            llm_cache=None,
        )


def test_uncached_llm_call_is_blocked_when_cache_exists_but_misses(tmp_path: Path) -> None:
    """Empty cache file with llm_enabled=True must still raise UncachedLlmCallError."""
    cache_path = tmp_path / "llm_cache.json"
    cache_path.write_text("{}\n", encoding="utf-8")
    cache = LlmTextCache(cache_path)

    with pytest.raises(UncachedLlmCallError, match="Uncached LLM call blocked"):
        render_template_text(
            "ransom_note_v1",
            seed=42,
            linked_evidence_ids=["EVID-miss"],
            slots={"user": "a", "host": "b"},
            llm_enabled=True,
            llm_cache=cache,
        )


def test_llm_cache_enforces_reproducibility(tmp_path: Path) -> None:
    cache_path = tmp_path / "llm_cache.json"
    cache = LlmTextCache(cache_path)
    cache.put(42, "ransom_note_v1", ["EVID-x"], "Cached paraphrase.")

    rendered = render_template_text(
        "ransom_note_v1",
        seed=42,
        linked_evidence_ids=["EVID-x"],
        slots={"user": "a", "host": "b"},
        llm_enabled=True,
        llm_cache=cache,
    )
    assert rendered == "Cached paraphrase."
    assert cache_path.is_file()


@pytest.mark.skipif(not COLONIAL_EVENTS.is_file(), reason="colonial canonical events missing")
def test_all_sources_build_deterministically(tmp_path: Path) -> None:
    def build_and_digest(root: Path) -> dict[str, str]:
        build_sources_from_file(COLONIAL_EVENTS, root / "data", _colonial_config())
        return {
            str(path.relative_to(root)): file_digest(path)
            for path in sorted((root / "data").rglob("*.ndjson"))
        }

    first = build_and_digest(tmp_path / "run1")
    second = build_and_digest(tmp_path / "run2")
    assert first == second
    assert first


def _minimal_events() -> list[CanonicalEvent]:
    return [
        CanonicalEvent(
            evidence_id="EVID-vss",
            ts="2024-06-03T10:00:00Z",
            host="FS-01",
            actor="attacker",
            kind="process",
            fields={
                "process_name": "vssadmin.exe",
                "command_line": "vssadmin delete shadows /all /quiet",
                "pid": 100,
            },
            record_id="evt-vss#0",
        ),
        CanonicalEvent(
            evidence_id="EVID-enc",
            ts="2024-06-03T10:10:00Z",
            host="FS-01",
            actor="attacker",
            kind="process",
            fields={
                "process_name": "darkside_svc.exe",
                "command_line": "darkside_svc.exe --encrypt \\\\FS-01\\Finance",
                "pid": 200,
            },
            record_id="evt-enc#0",
        ),
    ]


def test_sources_digest_stable_on_minimal_events(tmp_path: Path) -> None:
    events = _minimal_events()
    data_root = tmp_path / "data"
    config = SourceBuildConfig(seed=7, window_start=COLONIAL_WINDOW_START)

    from socbench.sources import build_sources

    build_sources(events, data_root, config)
    digests = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in data_root.rglob("*.ndjson")
    }
    build_sources(events, data_root, config)
    digests_repeat = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in data_root.rglob("*.ndjson")
    }
    assert digests == digests_repeat
