"""Windows Event XML to native EVTX conversion."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from lxml import etree

from socbench.raw._xml2evtx import (
    iter_xml_record_nodes,
    write_evtx_from_xml_path,
    write_evtx_from_xml_text,
)
from socbench.raw.errors import EvtxConversionError

_EVENT_ID_RE = re.compile(r"<(?:\{\S+\})?EventID>(\d+)</(?:\{\S+\})?EventID>")
_EVENT_RECORD_ID_RE = re.compile(r"<(?:\{\S+\})?EventRecordID>(\d+)</(?:\{\S+\})?EventRecordID>")
_TIME_CREATED_RE = re.compile(r"<(?:\{\S+\})?TimeCreated SystemTime='([^']+)'")
_TIME_CREATED_DQ_RE = re.compile(r'<(?:\{\S+\})?TimeCreated SystemTime="([^"]+)"')
_DATA_FIELD_SQ_RE = re.compile(r"<(?:\{\S+\})?Data Name='([^']+)'>([^<]*)</(?:\{\S+\})?Data>")
_DATA_FIELD_DQ_RE = re.compile(r'<(?:\{\S+\})?Data Name="([^"]+)">([^<]*)</(?:\{\S+\})?Data>')
_PROVIDER_NAME_SQ_RE = re.compile(r"<(?:\{\S+\})?Provider Name='([^']+)'")
_PROVIDER_NAME_DQ_RE = re.compile(r'<(?:\{\S+\})?Provider Name="([^"]+)"')
_COMPUTER_RE = re.compile(r"<(?:\{\S+\})?Computer>([^<]+)</(?:\{\S+\})?Computer>")
_CHANNEL_RE = re.compile(r"<(?:\{\S+\})?Channel>([^<]+)</(?:\{\S+\})?Channel>")
_EVENT_FRAGMENT_SPLIT = re.compile(r"(?=<Event[\s>])")


def convert_xml_file_to_evtx(xml_path: Path, evtx_path: Path) -> int:
    """Convert ``windows_event_security.xml`` to a native ``.evtx`` file."""
    try:
        return write_evtx_from_xml_path(xml_path, evtx_path)
    except ValueError as exc:
        raise EvtxConversionError(str(exc)) from exc
    except OSError as exc:
        raise EvtxConversionError(f"Failed to write EVTX {evtx_path}: {exc}") from exc


def convert_xml_text_to_evtx(xml_text: str, evtx_path: Path) -> int:
    """Convert in-memory Windows Event XML to a native ``.evtx`` file."""
    try:
        return write_evtx_from_xml_text(xml_text, evtx_path)
    except ValueError as exc:
        raise EvtxConversionError(str(exc)) from exc
    except OSError as exc:
        raise EvtxConversionError(f"Failed to write EVTX {evtx_path}: {exc}") from exc


def parse_xml_event_fields(xml_text: str) -> list[dict[str, Any]]:
    """Extract comparable per-event field maps from EF Windows Event XML."""
    records: list[dict[str, Any]] = []
    for node, err in iter_xml_record_nodes(xml_text):
        if err is not None:
            continue
        fragment = etree.tostring(node, encoding="unicode")
        records.append(_fields_from_event_fragment(fragment))
    return sorted(records, key=lambda item: str(item.get("EventRecordID", "")))


def parse_evtx_event_fields(evtx_path: Path) -> list[dict[str, Any]]:
    """Extract comparable per-event field maps from an EVTX file."""
    if sys.platform == "win32" and shutil.which("wevtutil") is not None:
        return _parse_evtx_with_wevtutil(evtx_path)
    return _parse_evtx_with_python_evtx(evtx_path)


def wevtutil_available() -> bool:
    """Return True when Windows ``wevtutil`` can query EVTX files."""
    return sys.platform == "win32" and shutil.which("wevtutil") is not None


def chainsaw_available() -> bool:
    """Return True when the Chainsaw CLI is on PATH."""
    try:
        proc = subprocess.run(
            ["chainsaw", "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return proc.returncode == 0


def compare_event_field_sets(
    source_records: list[dict[str, Any]],
    parsed_records: list[dict[str, Any]],
) -> list[str]:
    """Return human-readable mismatches between source and parsed event field maps."""
    mismatches: list[str] = []
    if len(source_records) != len(parsed_records):
        mismatches.append(
            f"event count mismatch: source={len(source_records)} parsed={len(parsed_records)}"
        )
    for index, source in enumerate(source_records):
        if index >= len(parsed_records):
            break
        parsed = parsed_records[index]
        for key in sorted(set(source) | set(parsed)):
            if source.get(key) != parsed.get(key):
                mismatches.append(
                    f"event[{index}] field {key!r}: source={source.get(key)!r} "
                    f"parsed={parsed.get(key)!r}"
                )
    return mismatches


def _fields_from_event_fragment(fragment: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for pattern, key in (
        (_EVENT_ID_RE, "EventID"),
        (_EVENT_RECORD_ID_RE, "EventRecordID"),
        (_TIME_CREATED_RE, "TimeCreated"),
        (_TIME_CREATED_DQ_RE, "TimeCreated"),
        (_PROVIDER_NAME_SQ_RE, "Provider"),
        (_PROVIDER_NAME_DQ_RE, "Provider"),
        (_COMPUTER_RE, "Computer"),
        (_CHANNEL_RE, "Channel"),
    ):
        match = pattern.search(fragment)
        if match and key not in fields:
            fields[key] = match.group(1)

    event_data: dict[str, str] = {}
    for name, value in _DATA_FIELD_SQ_RE.findall(fragment):
        event_data[name] = value
    for name, value in _DATA_FIELD_DQ_RE.findall(fragment):
        event_data[name] = value
    if event_data:
        fields["EventData"] = event_data
    return fields


def _parse_evtx_with_wevtutil(evtx_path: Path) -> list[dict[str, Any]]:
    proc = subprocess.run(
        [
            "wevtutil",
            "qe",
            str(evtx_path),
            "/lf:true",
            "/f:xml",
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise EvtxConversionError(
            f"wevtutil failed to read {evtx_path}: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    fragments = [chunk for chunk in _EVENT_FRAGMENT_SPLIT.split(proc.stdout) if "<Event" in chunk]
    records = [_fields_from_event_fragment(fragment) for fragment in fragments]
    return sorted(records, key=lambda item: str(item.get("EventRecordID", "")))


def _parse_evtx_with_python_evtx(evtx_path: Path) -> list[dict[str, Any]]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore[import-untyped]
    except ImportError as exc:
        raise EvtxConversionError(
            "EVTX parsing requires wevtutil on Windows or python-evtx elsewhere; "
            "install optional dependency binary-formats"
        ) from exc

    records: list[dict[str, Any]] = []
    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            records.append(_fields_from_event_fragment(record.xml()))
    return records
