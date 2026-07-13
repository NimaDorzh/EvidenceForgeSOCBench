"""Tests for SOC-bench stage bucketizing and WorldState interface (step 5)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from socbench.capture.models import CanonicalEvent
from socbench.sources import build_sources_from_file
from socbench.sources.models import SourceBuildConfig
from socbench.stage.bucketize import (
    bucketize_bundle,
    linked_evidence_stage_indices,
)
from socbench.stage.world_state import Intervention, StaticWorldState, WorldState
from socbench.truth.common import index_by_evidence_id, load_canonical_events, parse_ts, stage_of
from socbench.truth.panda import build_panda_manifest
from tests.socbench.colonial_fixtures import COLONIAL_EVENTS, COLONIAL_WINDOW_START

REPO_ROOT = Path(__file__).resolve().parents[2]


def _colonial_config(**overrides: object) -> SourceBuildConfig:
    base = {
        "seed": 42,
        "window_start": COLONIAL_WINDOW_START,
        "stage_minutes": 30,
    }
    base.update(overrides)
    return SourceBuildConfig.model_validate(base)


def _load_ndjson(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _build_colonial_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    data_root = bundle / "data"
    grader_root = bundle / "grader"
    grader_root.mkdir(parents=True)
    events_dst = grader_root / "canonical_events.ndjson"
    events_dst.write_text(COLONIAL_EVENTS.read_text(encoding="utf-8"), encoding="utf-8")
    build_sources_from_file(events_dst, data_root, _colonial_config())
    return bundle


def _stage_dir_digest(agent_root: Path) -> str:
    lines: list[str] = []
    for path in sorted(agent_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(agent_root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{rel}:{digest}")
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def test_world_state_interface_signatures() -> None:
    events = [
        CanonicalEvent(
            evidence_id="EVID-a",
            ts="2024-06-03T08:05:00Z",
            host="H1",
            actor="user",
            kind="process",
            record_id="EVID-a#0",
        ),
        CanonicalEvent(
            evidence_id="EVID-b",
            ts="2024-06-03T09:05:00Z",
            host="H2",
            actor="user",
            kind="process",
            record_id="EVID-b#0",
        ),
    ]
    state: WorldState = StaticWorldState.from_events(events, window_start=COLONIAL_WINDOW_START)
    intervention = Intervention(kind="isolate_host", targets=["H1"], at_stage=1)

    patched = state.apply(intervention)
    assert isinstance(patched, StaticWorldState)
    assert patched.events == events
    assert patched.interventions == (intervention,)

    tail = patched.replan_tail(from_stage=1)
    assert isinstance(tail, list)
    assert all(isinstance(item, CanonicalEvent) for item in tail)
    assert {item.evidence_id for item in tail} == {"EVID-b"}


def test_static_world_state_slice_through_unchanged() -> None:
    events = load_canonical_events(COLONIAL_EVENTS)
    state = StaticWorldState.from_events(events, window_start=COLONIAL_WINDOW_START)
    sliced = state.slice_through(1)
    assert sliced
    assert all(
        stage_of(event.ts, state.window_start, stage_minutes=state.stage_minutes) <= 1
        for event in sliced
    )


@pytest.mark.skipif(
    not COLONIAL_EVENTS.is_file(),
    reason="committed colonial fixture missing: tests/fixtures/bundles/colonial/",
)
def test_bucketize_creates_cumulative_stage_directories(tmp_path: Path) -> None:
    bundle = _build_colonial_bundle(tmp_path)
    result = bucketize_bundle(bundle, window_start=COLONIAL_WINDOW_START)

    assert result.stage_count == result.max_stage + 1
    for stage in range(result.max_stage + 1):
        stage_dir = result.agent_root / f"stage_{stage:02d}"
        assert stage_dir.is_dir()

    stage0_alerts = _load_ndjson(result.agent_root / "stage_00" / "data" / "siem" / "alerts.ndjson")
    stage_last = (
        result.agent_root / f"stage_{result.max_stage:02d}" / "data" / "siem" / "alerts.ndjson"
    )
    stage_last_alerts = _load_ndjson(stage_last)
    assert len(stage_last_alerts) >= len(stage0_alerts)


@pytest.mark.skipif(
    not COLONIAL_EVENTS.is_file(),
    reason="committed colonial fixture missing: tests/fixtures/bundles/colonial/",
)
def test_helpdesk_empty_before_min_stage_gate(tmp_path: Path) -> None:
    bundle = _build_colonial_bundle(tmp_path)
    result = bucketize_bundle(bundle, window_start=COLONIAL_WINDOW_START)
    events = load_canonical_events(bundle / "grader" / "canonical_events.ndjson")
    origin = result.window_start
    max_stage = max(stage_of(event.ts, origin) for event in events)
    half_stage = max_stage // 2

    for stage in range(half_stage):
        tickets_path = (
            result.agent_root / f"stage_{stage:02d}" / "data" / "helpdesk" / "tickets.ndjson"
        )
        assert _load_ndjson(tickets_path) == []


def test_helpdesk_min_stage_gate_suppresses_early_timestamp(tmp_path: Path) -> None:
    """Gate must block tickets even when ts alone would place them in an early stage."""
    bundle = tmp_path / "bundle"
    data_root = bundle / "data"
    grader_root = bundle / "grader"
    grader_root.mkdir(parents=True)
    data_root.mkdir(parents=True)

    events = [
        CanonicalEvent(
            evidence_id="EVID-early",
            ts="2024-06-03T08:05:00Z",
            host="FS-01",
            actor="attacker",
            kind="process",
            record_id="EVID-early#0",
        ),
        CanonicalEvent(
            evidence_id="EVID-late",
            ts="2024-06-03T10:30:00Z",
            host="FS-01",
            actor="attacker",
            kind="process",
            record_id="EVID-late#0",
        ),
    ]
    canonical_path = grader_root / "canonical_events.ndjson"
    canonical_path.write_text(
        "\n".join(event.model_dump_json() for event in events) + "\n",
        encoding="utf-8",
    )

    early_ticket_ts = "2024-06-03T08:35:00Z"  # stage 1 from 08:00 origin
    min_gate = 4
    ticket = {
        "ticket_id": "HD-GATE-TEST",
        "ts": early_ticket_ts,
        "user": "j.walsh",
        "host": "WKS-01",
        "category": "incident",
        "priority": "high",
        "text": "Synthetic early-ts ticket for min_stage_gate regression.",
        "related_host": "FS-01",
        "min_stage_gate": min_gate,
        "__grader_metadata": {
            "linked_evidence_ids": ["EVID-late"],
            "latency_applied_ms": 0,
            "template_id": "ransom_note_v1",
        },
    }
    helpdesk_path = data_root / "helpdesk" / "tickets.ndjson"
    helpdesk_path.parent.mkdir(parents=True)
    helpdesk_path.write_text(json.dumps(ticket, sort_keys=True) + "\n", encoding="utf-8")

    origin = parse_ts(COLONIAL_WINDOW_START)
    assert stage_of(early_ticket_ts, origin) == 1
    result = bucketize_bundle(bundle, window_start=COLONIAL_WINDOW_START)
    assert result.max_stage >= min_gate

    for stage in range(min_gate):
        stage_tickets = _load_ndjson(
            result.agent_root / f"stage_{stage:02d}" / "data" / "helpdesk" / "tickets.ndjson"
        )
        assert [row.get("ticket_id") for row in stage_tickets] == [], (
            f"ticket with ts in stage 1 must be suppressed by min_stage_gate={min_gate} "
            f"in agent stage {stage}"
        )

    for stage in range(min_gate, result.max_stage + 1):
        stage_tickets = _load_ndjson(
            result.agent_root / f"stage_{stage:02d}" / "data" / "helpdesk" / "tickets.ndjson"
        )
        ticket_ids = [row.get("ticket_id") for row in stage_tickets]
        assert "HD-GATE-TEST" in ticket_ids, (
            f"ticket must appear once agent stage {stage} reaches min_stage_gate={min_gate}"
        )

@pytest.mark.skipif(
    not COLONIAL_EVENTS.is_file(),
    reason="committed colonial fixture missing: tests/fixtures/bundles/colonial/",
)
def test_cti_user_linked_rows_gate_by_timestamp_only(tmp_path: Path) -> None:
    bundle = _build_colonial_bundle(tmp_path)
    result = bucketize_bundle(bundle, window_start=COLONIAL_WINDOW_START)
    origin = result.window_start

    full_cti = _load_ndjson(bundle / "data" / "cti" / "feeds" / "incident_correlation.ndjson")
    linked_rows = [row for row in full_cti if row.get("__grader_metadata")]
    assert linked_rows
    assert all("min_stage_gate" not in row for row in linked_rows)

    late_linked = [row for row in linked_rows if stage_of(str(row["ts"]), origin) > 0]
    if not late_linked:
        pytest.skip("all user-linked CTI rows fall in stage 0 for this fixture")
    first_linked = late_linked[0]
    first_stage = stage_of(str(first_linked["ts"]), origin)
    early_path = (
        result.agent_root
        / f"stage_{first_stage - 1:02d}"
        / "data"
        / "cti"
        / "feeds"
        / "incident_correlation.ndjson"
    )
    early_rows = _load_ndjson(early_path)
    early_ids = {row.get("record_id") for row in early_rows}
    assert first_linked["record_id"] not in early_ids


@pytest.mark.skipif(
    not COLONIAL_EVENTS.is_file(),
    reason="committed colonial fixture missing: tests/fixtures/bundles/colonial/",
)
def test_bucketize_records_carry_stage_index(tmp_path: Path) -> None:
    bundle = _build_colonial_bundle(tmp_path)
    result = bucketize_bundle(bundle, window_start=COLONIAL_WINDOW_START)
    stage_dir = result.agent_root / f"stage_{result.max_stage:02d}"
    alerts = _load_ndjson(stage_dir / "data" / "siem" / "alerts.ndjson")
    assert alerts
    assert "stage_index" in alerts[0]
    canonical = _load_ndjson(stage_dir / "canonical_events.ndjson")
    assert canonical
    assert "stage_index" in canonical[0]


@pytest.mark.skipif(
    not COLONIAL_EVENTS.is_file(),
    reason="committed colonial fixture missing: tests/fixtures/bundles/colonial/",
)
def test_bucketize_is_deterministic_by_sha256(tmp_path: Path) -> None:
    bundle = _build_colonial_bundle(tmp_path)
    first = bucketize_bundle(bundle, window_start=COLONIAL_WINDOW_START, agent_root=tmp_path / "a1")
    second = bucketize_bundle(
        bundle, window_start=COLONIAL_WINDOW_START, agent_root=tmp_path / "a2"
    )
    assert _stage_dir_digest(first.agent_root) == _stage_dir_digest(second.agent_root)


@pytest.mark.skipif(
    not COLONIAL_EVENTS.is_file(),
    reason="committed colonial fixture missing: tests/fixtures/bundles/colonial/",
)
def test_no_linked_evidence_leaks_into_earlier_agent_stages(tmp_path: Path) -> None:
    bundle = _build_colonial_bundle(tmp_path)
    result = bucketize_bundle(bundle, window_start=COLONIAL_WINDOW_START)
    events = load_canonical_events(bundle / "grader" / "canonical_events.ndjson")
    events_by_id = index_by_evidence_id(events)
    origin = result.window_start

    for stage in range(result.max_stage + 1):
        stage_dir = result.agent_root / f"stage_{stage:02d}"
        for ndjson_path in stage_dir.rglob("*.ndjson"):
            if ndjson_path.name == "canonical_events.ndjson":
                continue
            for record in _load_ndjson(ndjson_path):
                record_stage = record.get("stage_index")
                if isinstance(record_stage, int):
                    assert record_stage <= stage, (
                        f"{ndjson_path}: record stage_index {record_stage} visible in stage {stage}"
                    )
                linked_stages = linked_evidence_stage_indices(
                    record,
                    events_by_id,
                    origin,
                    stage_minutes=result.stage_minutes,
                )
                for linked_stage in linked_stages:
                    assert linked_stage <= stage, (
                        f"{ndjson_path}: linked evidence from stage {linked_stage} "
                        f"visible in agent stage {stage}"
                    )


@pytest.mark.skipif(
    not COLONIAL_EVENTS.is_file(),
    reason="committed colonial fixture missing: tests/fixtures/bundles/colonial/",
)
def test_panda_regression_after_world_state_refactor(tmp_path: Path) -> None:
    events = load_canonical_events(COLONIAL_EVENTS)
    state = StaticWorldState.from_events(events, window_start=COLONIAL_WINDOW_START)
    manifest = build_panda_manifest(state, window_start=COLONIAL_WINDOW_START)
    assert manifest["stages"]
    assert manifest["stages"][0]["incident_phase"] == "initial_access"
