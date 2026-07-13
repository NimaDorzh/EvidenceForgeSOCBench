"""Round-trip tests for native host-log binary conversion."""

from __future__ import annotations

from pathlib import Path

import pytest

from socbench.raw.evtx import (
    compare_event_field_sets,
    convert_xml_file_to_evtx,
    parse_evtx_event_fields,
    parse_xml_event_fields,
)
from socbench.raw.host_logs import (
    bucketize_host_logs,
    convert_staged_host_logs,
    copy_ef_host_logs,
    discover_host_log_files,
)
from socbench.raw.journal import (
    JournalBackendUnavailableError,
    compare_syslog_journal_records,
    convert_syslog_file_to_journal,
    docker_available,
    parse_journal_fields,
    parse_syslog_lines,
    wsl_journal_remote_available,
)
from socbench.truth.common import load_canonical_events, resolve_window_start, stage_of

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_XML = REPO_ROOT / "tests" / "fixtures" / "eval" / "good" / "windows_event_security.xml"
FIXTURE_SYSLOG = REPO_ROOT / "tests" / "fixtures" / "eval" / "good" / "syslog.log"
COLONIAL_DATA = REPO_ROOT / "scenarios" / "colonial-pipeline" / "data"
COLONIAL_EVENTS = (
    REPO_ROOT / "scenarios" / "colonial-pipeline" / "grader" / "canonical_events.ndjson"
)
COLONIAL_WINDOW_START = "2024-06-03T08:00:00Z"

pytest.importorskip("lxml")


def _journal_backend_available() -> bool:
    return docker_available() or wsl_journal_remote_available()


@pytest.mark.binary_formats
def test_discover_colonial_host_logs() -> None:
    if not COLONIAL_DATA.is_dir():
        pytest.skip("colonial EF data missing")
    discovered = discover_host_log_files(COLONIAL_DATA)
    assert any(path.name == "windows_event_security.xml" for path in discovered)
    assert any(path.name == "syslog.log" for path in discovered)


@pytest.mark.binary_formats
def test_evtx_roundtrip_fixture_fields_match(tmp_path: Path) -> None:
    xml_text = FIXTURE_XML.read_text(encoding="utf-8")
    source_fields = parse_xml_event_fields(xml_text)
    assert source_fields

    evtx_path = tmp_path / "windows_event_security.evtx"
    event_count = convert_xml_file_to_evtx(FIXTURE_XML, evtx_path)
    assert event_count == len(source_fields)
    assert evtx_path.stat().st_size > 0

    parsed_fields = parse_evtx_event_fields(evtx_path)
    mismatches = compare_event_field_sets(source_fields, parsed_fields)
    assert mismatches == [], "\n".join(mismatches)


@pytest.mark.binary_formats
@pytest.mark.skipif(not _journal_backend_available(), reason="Docker/WSL journal backend unavailable")
def test_journal_roundtrip_fixture_fields_match(tmp_path: Path) -> None:
    syslog_text = FIXTURE_SYSLOG.read_text(encoding="utf-8")
    syslog_records = parse_syslog_lines(syslog_text)
    assert syslog_records

    syslog_path = tmp_path / "syslog.log"
    journal_path = tmp_path / "system.journal"
    syslog_path.write_text(syslog_text, encoding="utf-8")

    record_count = convert_syslog_file_to_journal(syslog_path, journal_path)
    assert record_count == len(syslog_records)
    assert journal_path.stat().st_size > 0

    journal_records = parse_journal_fields(journal_path)
    mismatches = compare_syslog_journal_records(syslog_records, journal_records)
    assert mismatches == [], "\n".join(mismatches)


@pytest.mark.binary_formats
@pytest.mark.skipif(not COLONIAL_DATA.is_dir(), reason="colonial EF data missing")
def test_host_log_stage_slice_is_cumulative(tmp_path: Path) -> None:
    events = load_canonical_events(COLONIAL_EVENTS)
    origin = resolve_window_start(events, COLONIAL_WINDOW_START)
    data_root = tmp_path / "data"
    copy_ef_host_logs(COLONIAL_DATA, data_root)
    max_stage = max(stage_of(event.ts, origin, stage_minutes=30) for event in events)

    digests = bucketize_host_logs(
        data_root,
        tmp_path / "agent_raw",
        window_start=origin,
        stage_minutes=30,
        max_stage=max_stage,
    )
    assert digests["stage_00"]
    assert digests[f"stage_{max_stage:02d}"]

    stage00_xml = (
        tmp_path / "agent_raw" / "stage_00" / "data" / "FS-01.colonial-energy.local"
        / "windows_event_security.xml"
    )
    stage_last_xml = (
        tmp_path
        / "agent_raw"
        / f"stage_{max_stage:02d}"
        / "data"
        / "FS-01.colonial-energy.local"
        / "windows_event_security.xml"
    )
    assert stage00_xml.is_file()
    assert stage_last_xml.is_file()
    assert len(stage_last_xml.read_text(encoding="utf-8")) >= len(
        stage00_xml.read_text(encoding="utf-8")
    )


@pytest.mark.binary_formats
@pytest.mark.slow
@pytest.mark.skipif(not COLONIAL_DATA.is_dir(), reason="colonial EF data missing")
@pytest.mark.skipif(not _journal_backend_available(), reason="Docker/WSL journal backend unavailable")
def test_convert_staged_colonial_host_logs(tmp_path: Path) -> None:
    events = load_canonical_events(COLONIAL_EVENTS)
    origin = resolve_window_start(events, COLONIAL_WINDOW_START)
    data_root = tmp_path / "data"
    agent_raw = tmp_path / "agent_raw"
    copy_ef_host_logs(COLONIAL_DATA, data_root)
    max_stage = max(stage_of(event.ts, origin, stage_minutes=30) for event in events)
    bucketize_host_logs(
        data_root,
        agent_raw,
        window_start=origin,
        stage_minutes=30,
        max_stage=max_stage,
    )

    result = convert_staged_host_logs(agent_raw)
    assert result.converted_files >= 2
    assert not any(agent_raw.rglob("windows_event_security.xml"))
    assert not any(agent_raw.rglob("syslog.log"))
    assert any(agent_raw.rglob("windows_event_security.evtx"))
    assert any(agent_raw.rglob("system.journal"))


@pytest.mark.binary_formats
def test_journal_backend_unavailable_raises_clear_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "socbench.raw.journal.docker_available",
        lambda: False,
    )
    monkeypatch.setattr(
        "socbench.raw.journal.wsl_journal_remote_available",
        lambda: False,
    )
    syslog_path = tmp_path / "syslog.log"
    syslog_path.write_text(FIXTURE_SYSLOG.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(JournalBackendUnavailableError):
        convert_syslog_file_to_journal(syslog_path, tmp_path / "system.journal")
