"""Windows Event XML to native EVTX conversion."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

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
# Bytes from record signature through the BinXml fragment header.
_RECORD_BINXML_OFFSET = 0x1C


def convert_xml_file_to_evtx(xml_path: Path, evtx_path: Path) -> int:
    """Convert ``windows_event_security.xml`` to a native ``.evtx`` file."""
    from socbench.raw._xml2evtx import write_evtx_from_xml_path

    try:
        return write_evtx_from_xml_path(xml_path, evtx_path)
    except ValueError as exc:
        raise EvtxConversionError(str(exc)) from exc
    except OSError as exc:
        raise EvtxConversionError(f"Failed to write EVTX {evtx_path}: {exc}") from exc


def convert_xml_text_to_evtx(xml_text: str, evtx_path: Path) -> int:
    """Convert in-memory Windows Event XML to a native ``.evtx`` file."""
    from socbench.raw._xml2evtx import write_evtx_from_xml_text

    try:
        return write_evtx_from_xml_text(xml_text, evtx_path)
    except ValueError as exc:
        raise EvtxConversionError(str(exc)) from exc
    except OSError as exc:
        raise EvtxConversionError(f"Failed to write EVTX {evtx_path}: {exc}") from exc


def parse_xml_event_fields(xml_text: str) -> list[dict[str, Any]]:
    """Extract comparable per-event field maps from EF Windows Event XML."""
    from lxml import etree

    from socbench.raw._xml2evtx import iter_xml_record_nodes

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
        try:
            return _parse_evtx_with_wevtutil(evtx_path)
        except EvtxConversionError:
            pass
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


def _jpcert_open_start_element_node(record: Any, chunk: Any) -> Any:
    """Parse JPCERT 9-byte element headers (no MS-EVEN6 dependency word)."""
    from Evtx import Nodes
    from Evtx.BinaryParser import memoize

    offset = record.offset() + _RECORD_BINXML_OFFSET

    class _JpcertOpenStartElementNode(Nodes.BXmlNode):
        """OpenStartElement with JPCERT's 9-byte header instead of MS-EVEN6's 11-byte."""

        def __init__(self, buf: Any, node_offset: int, node_chunk: Any, parent: Any) -> None:
            super().__init__(buf, node_offset, node_chunk, parent)
            self.declare_field("byte", "token", 0x0)
            self.declare_field("dword", "size", 0x1)
            self.declare_field("dword", "string_offset", 0x5)
            self._tag_length = 9
            if self.flags() & 0x04:
                self._tag_length += 4
            if self.string_offset() > self.offset() - self._chunk._offset:
                new_string = self._chunk.add_string(self.string_offset(), parent=self)
                self._tag_length += new_string.length()

        def flags(self) -> int:
            return self.token() >> 4

        @memoize
        def tag_name(self) -> str:
            return self._chunk.strings()[self.string_offset()].string()

        def tag_length(self) -> int:
            return self._tag_length

        def _child_node_class(self, token: int) -> type[Any]:
            if token == Nodes.SYSTEM_TOKENS.OpenStartElementToken:
                return _JpcertOpenStartElementNode
            return Nodes.node_dispatch_table[token]

        def _children(
            self,
            max_children: int | None = None,
            end_tokens: list[int] | None = None,
        ) -> list[Any]:
            import itertools

            if end_tokens is None:
                end_tokens = [Nodes.SYSTEM_TOKENS.EndOfStreamToken]
            ret: list[Any] = []
            ofs = self.tag_length()
            gen = list(range(max_children)) if max_children else itertools.count()
            for _ in gen:
                token = self.unpack_byte(ofs) & 0x0F
                handler = self._child_node_class(token)
                child = handler(self._buf, self.offset() + ofs, self._chunk, self)
                ret.append(child)
                ofs += child.length()
                if token in end_tokens:
                    break
                if child.find_end_of_stream():
                    break
            return ret

        def children(self) -> list[Any]:
            return self._children(
                end_tokens=[
                    Nodes.SYSTEM_TOKENS.CloseElementToken,
                    Nodes.SYSTEM_TOKENS.CloseEmptyElementToken,
                ]
            )

    return _JpcertOpenStartElementNode(record._buf, offset, chunk, record)


def _render_fragment_binxml(record: Any, chunk: Any) -> str:
    """Render JPCERT-style non-template BinXML using python-evtx node walkers."""
    from Evtx import Nodes
    from Evtx.Views import escape_value

    root = _jpcert_open_start_element_node(record, chunk)

    def walk(node: Any, acc: list[str]) -> None:
        if isinstance(node, Nodes.OpenStartElementNode) or hasattr(node, "_child_node_class"):
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, Nodes.AttributeNode):
                    acc.append(" ")
                    acc.append(child.attribute_name().string())
                    acc.append('="')
                    walk(child.attribute_value(), acc)
                    acc.append('"')
            acc.append(">")
            for child in node.children():
                walk(child, acc)
            acc.append("</")
            acc.append(node.tag_name())
            acc.append(">")
        elif isinstance(node, Nodes.ValueNode):
            acc.append(escape_value(node.children()[0].string()))
        elif isinstance(
            node,
            (
                Nodes.CloseStartElementNode,
                Nodes.CloseEmptyElementNode,
                Nodes.CloseElementNode,
                Nodes.AttributeNode,
                Nodes.EndOfStreamNode,
                Nodes.StreamStartNode,
            ),
        ):
            return
        elif isinstance(
            node,
            (
                Nodes.TemplateInstanceNode,
                Nodes.NormalSubstitutionNode,
                Nodes.ConditionalSubstitutionNode,
            ),
        ):
            msg = f"unexpected BinXML token in fragment record: {type(node).__name__}"
            raise EvtxConversionError(msg)

    parts: list[str] = []
    walk(root, parts)
    return "".join(parts)


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
        chunk = next(log.chunks())
        for record in log.records():
            fragment = _render_fragment_binxml(record, chunk)
            records.append(_fields_from_event_fragment(fragment))
    return records
