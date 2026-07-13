"""Stage-gated host log slicing and native binary conversion."""

from __future__ import annotations

import logging
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from evidenceforge.utils.paths import safe_write_text
from socbench.raw.errors import (
    EvtxConversionError,
    JournalBackendUnavailableError,
    JournalConversionError,
)
from socbench.sources.common import file_digest
from socbench.truth.common import stage_of

logger = logging.getLogger(__name__)

WINDOWS_SECURITY_XML = "windows_event_security.xml"
WINDOWS_SECURITY_EVTX = "windows_event_security.evtx"
SYSLOG_LOG = "syslog.log"
SYSTEM_JOURNAL = "system.journal"

_HOST_LOG_FILENAMES = frozenset({WINDOWS_SECURITY_XML, SYSLOG_LOG})
_SYNTHETIC_SUBDIRS = frozenset(
    {"siem", "hostmetrics", "vss", "helpdesk", "cti", "process_telemetry"}
)

_XML_EVENT_SPLIT = re.compile(
    r"(?=<Event xmlns=['\"]http://schemas\.microsoft\.com/win/2004/08/events/event['\"]>)"
)
_XML_TIME_CREATED_RE = re.compile(r'<TimeCreated SystemTime="([^"]+)"')
_SYSLOG_TS_RE = re.compile(r"^<\d+>\d+\s+(\S+)")


@dataclass(frozen=True, slots=True)
class HostLogConvertResult:
    """Summary of native host-log conversion under an agent stage tree."""

    converted_files: int
    skipped_files: int
    digests: dict[str, str]


def discover_host_log_files(data_root: Path) -> list[Path]:
    """Return relative host-log paths under an EF ``data/`` tree."""
    data_root = data_root.resolve()
    if not data_root.is_dir():
        return []
    discovered: list[Path] = []
    for path in sorted(data_root.rglob("*")):
        if not path.is_file() or path.name not in _HOST_LOG_FILENAMES:
            continue
        rel = path.relative_to(data_root)
        if rel.parts and rel.parts[0] in _SYNTHETIC_SUBDIRS:
            continue
        discovered.append(rel)
    return discovered


def copy_ef_host_logs(source_data_root: Path, dest_data_root: Path) -> list[Path]:
    """Copy EF-generated host text logs into a staging ``data/`` tree."""
    source_data_root = source_data_root.resolve()
    dest_data_root = dest_data_root.resolve()
    copied: list[Path] = []
    for rel_path in discover_host_log_files(source_data_root):
        src = source_data_root / rel_path
        dst = dest_data_root / rel_path
        if not src.is_file():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(rel_path)
    return copied


def bucketize_host_logs(
    data_root: Path,
    out_root: Path,
    *,
    window_start: datetime,
    stage_minutes: int,
    max_stage: int,
) -> dict[str, dict[str, str]]:
    """Slice host text logs into cumulative ``agent/stage_XX/data`` directories."""
    data_root = data_root.resolve()
    out_root = out_root.resolve()
    stage_digests: dict[str, dict[str, str]] = {}
    host_logs = discover_host_log_files(data_root)
    if not host_logs:
        return stage_digests

    loaded: dict[Path, str] = {
        rel_path: (data_root / rel_path).read_text(encoding="utf-8") for rel_path in host_logs
    }

    for stage in range(max_stage + 1):
        stage_name = f"stage_{stage:02d}"
        stage_data_root = out_root / stage_name / "data"
        stage_digests[stage_name] = {}
        for rel_path, full_text in loaded.items():
            sliced = _slice_host_log_text(
                rel_path,
                full_text,
                agent_stage=stage,
                window_start=window_start,
                stage_minutes=stage_minutes,
            )
            if not sliced.strip():
                continue
            out_path = stage_data_root / rel_path
            safe_write_text(out_path, sliced, encoding="utf-8")
            stage_digests[stage_name][str(rel_path).replace("\\", "/")] = file_digest(out_path)
    return stage_digests


def convert_staged_host_logs(agent_root: Path, *, remove_text_sources: bool = True) -> HostLogConvertResult:
    """Convert staged host text logs to native ``.evtx`` / ``.journal`` artifacts."""
    agent_root = agent_root.resolve()
    converted = 0
    skipped = 0
    digests: dict[str, str] = {}

    for stage_dir in sorted(agent_root.glob("stage_*")):
        data_root = stage_dir / "data"
        if not data_root.is_dir():
            continue
        for rel_path in discover_host_log_files(data_root):
            src = data_root / rel_path
            if not src.is_file():
                continue
            try:
                if rel_path.name == WINDOWS_SECURITY_XML:
                    from socbench.raw.evtx import convert_xml_file_to_evtx

                    dst = src.with_name(WINDOWS_SECURITY_EVTX)
                    event_count = convert_xml_file_to_evtx(src, dst)
                    logger.info("Converted %s (%s events) -> %s", src, event_count, dst)
                elif rel_path.name == SYSLOG_LOG:
                    from socbench.raw.journal import convert_syslog_file_to_journal

                    dst = src.with_name(SYSTEM_JOURNAL)
                    record_count = convert_syslog_file_to_journal(src, dst)
                    logger.info("Converted %s (%s records) -> %s", src, record_count, dst)
                else:
                    skipped += 1
                    continue
            except (EvtxConversionError, JournalConversionError, JournalBackendUnavailableError, OSError) as exc:
                logger.warning("Skipping native conversion for %s: %s", src, exc)
                skipped += 1
                continue
            converted += 1
            rel_digest = dst.relative_to(agent_root).as_posix()
            digests[rel_digest] = file_digest(dst)
            if remove_text_sources:
                src.unlink()

    return HostLogConvertResult(
        converted_files=converted,
        skipped_files=skipped,
        digests=digests,
    )


def _slice_host_log_text(
    rel_path: Path,
    text: str,
    *,
    agent_stage: int,
    window_start: datetime,
    stage_minutes: int,
) -> str:
    if rel_path.name == WINDOWS_SECURITY_XML:
        return _slice_windows_event_xml(text, agent_stage, window_start, stage_minutes)
    if rel_path.name == SYSLOG_LOG:
        return _slice_syslog_log(text, agent_stage, window_start, stage_minutes)
    return ""


def _slice_windows_event_xml(
    text: str,
    agent_stage: int,
    window_start: datetime,
    stage_minutes: int,
) -> str:
    header = ""
    if text.lstrip().startswith("<?xml"):
        header = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    chunks = _XML_EVENT_SPLIT.split(text)
    visible_events: list[str] = []
    for chunk in chunks:
        stripped = chunk.strip()
        if not stripped.startswith("<Event "):
            continue
        ts_match = _XML_TIME_CREATED_RE.search(chunk)
        if ts_match is None:
            continue
        if stage_of(ts_match.group(1), window_start, stage_minutes=stage_minutes) > agent_stage:
            continue
        visible_events.append(chunk.strip())
    if not visible_events:
        return ""
    body = "\n".join(visible_events)
    return f"{header}<Events>\n{body}\n</Events>\n"


def _slice_syslog_log(
    text: str,
    agent_stage: int,
    window_start: datetime,
    stage_minutes: int,
) -> str:
    visible_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        ts_match = _SYSLOG_TS_RE.match(stripped)
        if ts_match is None:
            continue
        if stage_of(ts_match.group(1), window_start, stage_minutes=stage_minutes) > agent_stage:
            continue
        visible_lines.append(stripped)
    if not visible_lines:
        return ""
    return "\n".join(visible_lines) + "\n"
