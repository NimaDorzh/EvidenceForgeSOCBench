"""Vendored XML-to-EVTX encoder (BSD-3-Clause, JPCERTCC/xml2evtx).

See ``NOTICE-xml2evtx.txt`` for attribution. This module is intentionally
self-contained so SOC-bench can build native EVTX without Windows Event Log API
imports or admin privileges.
"""

from __future__ import annotations

import logging
import re
import time
import zlib
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from struct import pack

from lxml import etree

logger = logging.getLogger(__name__)

EVTX_HEADER_SIGNATURE = 0x456C6646696C6500
EVTX_CHUNK_HEADER_SIGNATURE = 0x456C6643686E6B00
EVTX_EVENT_RECORD_HEADER_SIGNATURE = 0x2A2A0000
FLAGMENT_HEADER = 0x0F010100
EVTX_MAJOR_VERSION = 0x0003
EVTX_MINOR_VERSION = 0x0002
MAX_CHUNK_SIZE = 0x10000
HEADER_SIZE = 128
HEADER_BLOCK_SIZE = 4096
START_EVENT_RECORD_ID = 1

TOKEN_TYPE = {
    "BinXmlTokenEOF": 0x00,
    "BinXmlTokenOpenStartElementTag_noAttribute": 0x01,
    "BinXmlTokenCloseStartElementTag": 0x02,
    "BinXmlTokenCloseEmptyElementTag": 0x03,
    "BinXmlTokenEndElementTag": 0x04,
    "BinXmlTokenValue": 0x05,
    "BinXmlTokenAttribute": 0x06,
    "BinXmlTokenCDATASection": 0x07,
    "BinXmlTokenCharRef": 0x08,
    "BinXmlTokenEntityRef": 0x09,
    "BinXmlTokenPITarget": 0x0A,
    "BinXmlTokenPIData": 0x0B,
    "BinXmlTokenTemplateInstance": 0x0C,
    "BinXmlTokenNormalSubstitution": 0x0D,
    "BinXmlTokenOptionalSubstitution": 0x0E,
    "BinXmlFragmentHeaderToken": 0x0F,
    "BinXmlTokenOpenStartElementTag_Attribute": 0x41,
    "BinXmlTokenValue_Next": 0x45,
    "BinXmlTokenAttribute_Next": 0x46,
}

VALUE_TYPE = {
    "NullType": 0x00,
    "StringType": 0x01,
    "AnsiStringType": 0x02,
    "Int8Type": 0x03,
    "UInt8Type": 0x04,
    "Int16Type": 0x05,
    "UInt16Type": 0x06,
    "Int32Type": 0x07,
    "UInt32Type": 0x08,
    "Int64Type": 0x09,
    "UInt64Type": 0x0A,
    "Real32Type": 0x0B,
    "Real64Type": 0x0C,
    "BoolType": 0x0D,
    "BinaryType": 0x0E,
    "GuidType": 0x0F,
    "SizeTType": 0x10,
    "FileTimeType": 0x11,
    "SysTimeType": 0x12,
    "SidType": 0x13,
    "HexInt32Type": 0x14,
    "HexInt64Type": 0x15,
    "EvtHandle": 0x20,
    "BinXmlType": 0x21,
    "EvtXml": 0x22,
}

EVTX_HEADER = {
    "signature": (">Q", EVTX_HEADER_SIGNATURE),
    "first_chunk_number": ("Q", 0),
    "last_chunk_number": ("Q", None),
    "next_record_identifier": ("Q", None),
    "header_size": ("I", HEADER_SIZE),
    "minor_version": ("H", EVTX_MINOR_VERSION),
    "major_version": ("H", EVTX_MAJOR_VERSION),
    "header_block_size": ("H", HEADER_BLOCK_SIZE),
    "number_of_chunks": ("H", None),
    "unknown1": ("76s", b"\x00" * 76),
    "file_flags": ("I", 0x0001),
    "checksum": ("I", None),
    "unknown2": ("3968s", b"\x00" * 3968),
}

EVTX_CHUNK_HEADER = {
    "signature": (">Q", EVTX_CHUNK_HEADER_SIGNATURE),
    "first_event_record_number": ("Q", 0x01),
    "last_event_record_number": ("Q", None),
    "first_event_record_identifier": ("Q", START_EVENT_RECORD_ID),
    "last_event_record_identifier": ("Q", None),
    "header_size": ("I", HEADER_SIZE),
    "last_event_record_offset": ("I", 0),
    "free_space_offset": ("I", None),
    "event_records_checksum": ("I", None),
    "unknown1": ("64s", b"\x00" * 64),
    "unknown2": ("I", 0x01),
    "checksum": ("I", None),
}

EVTX_EVENT_RECORD_HEADER = {
    "signature": (">I", EVTX_EVENT_RECORD_HEADER_SIGNATURE),
    "size": ("I", None),
    "identifier": ("Q", None),
    "written_time": ("Q", None),
}

BINXML_TEMPLATE_DEFINITION = {
    "unknown1": ("B", 0x01),
    "template_identifier_4": ("4s", None),
    "template_definition_data_offset": ("I", 0x77777777),
    "next_template_offset": ("I", 0),
    "template_identifier": ("16s", None),
    "data_size": ("I", None),
}

BINXML_ELEMENT_START = {
    "open_start_element_tag_token": ("B", None),
    "data_size": ("I", None),
    "element_name_offset": ("I", 0x99999999),
}

BINXML_NAME = {
    "unknown": ("I", 0),
    "name_hash": ("H", None),
    "number_of_characters": ("H", None),
}

BINXML_ATTRIBUTE = {
    "attribute_token": ("B", None),
    "attribute_name_offset": ("I", 0x88888888),
}

BINXML_VALUE_TEXT = {
    "value_token": ("B", TOKEN_TYPE["BinXmlTokenValue"]),
    "value_type": ("B", VALUE_TYPE["StringType"]),
    "data_size": ("H", None),
}

_EVENT_SPLIT = re.compile(
    r"<Event xmlns=['\"]http://schemas\.microsoft\.com/win/2004/08/events/event['\"]>"
)


def write_evtx_from_xml_path(xml_path: Path, evtx_path: Path) -> int:
    """Convert an EF-style Windows Event XML file to a native EVTX container."""
    xml_text = xml_path.read_text(encoding="utf-8")
    return write_evtx_from_xml_text(xml_text, evtx_path)


def write_evtx_from_xml_text(xml_text: str, evtx_path: Path) -> int:
    """Convert Windows Event XML text to a native EVTX container."""
    total_event_count, total_chunk_count, evtx_chunk = _process_xml_text(xml_text)
    if total_event_count == 0:
        msg = "No Windows Event XML records found to convert"
        raise ValueError(msg)
    evtx_data = _create_evtx(evtx_chunk, total_event_count, total_chunk_count)
    evtx_path = evtx_path.resolve()
    evtx_path.parent.mkdir(parents=True, exist_ok=True)
    evtx_path.write_bytes(evtx_data)
    return total_event_count


def _to_wordpack(str_name: str) -> bytes:
    data = b""
    for letter in str_name:
        data += pack("B", ord(letter))
        data += pack("B", 0)
    return data


def _to_lxml(record_xml: str) -> etree._Element:
    parser = etree.XMLParser(resolve_entities=False)
    return etree.fromstring(record_xml.encode("utf-8"), parser)


def _normalize_xml_text(xml_text: str) -> str:
    cleaned = xml_text
    for token in (
        '<?xml version="1.0" encoding="utf-8" standalone="yes"?>',
        '<?xml version="1.0" encoding="utf-8"?>',
        "</Events>",
        "<Events>",
    ):
        cleaned = cleaned.replace(token, "")
    return cleaned


def iter_xml_record_nodes(xml_text: str) -> Iterator[tuple[etree._Element | str, Exception | None]]:
    """Yield parsed Event nodes from EF-style Windows Event XML."""
    xdata = _normalize_xml_text(xml_text)
    xml_list = _EVENT_SPLIT.split(xdata)
    for fragment in xml_list:
        if fragment.strip().startswith("<System>"):
            try:
                yield (
                    _to_lxml(
                        '<?xml version="1.0" encoding="utf-8" standalone="yes" ?>'
                        f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">{fragment}'
                    ),
                    None,
                )
            except etree.XMLSyntaxError as exc:
                yield fragment, exc


def _getnttime(utime: datetime) -> int:
    mintime = time.mktime(utime.timetuple())
    namintime = int(mintime + 11644473600)
    return int(round(namintime * 10000000))


def _calc_name_hash(str_name: str) -> int:
    hash_val = 0
    for char in str_name:
        hash_val = hash_val * 65599 + ord(char)
    return hash_val & 0xFFFF


def _create_event_details(node_1st_element: etree._Element) -> bytes:
    event_details = b""
    for node_2nd_element in node_1st_element:
        event_details_data = _create_name_chunk(node_2nd_element.tag)
        if node_2nd_element.text:
            token_close = TOKEN_TYPE["BinXmlTokenEndElementTag"]
            value_text = pack("B", TOKEN_TYPE["BinXmlTokenCloseStartElementTag"]) + _create_value_chunk(
                node_2nd_element.text
            )
        else:
            token_close = TOKEN_TYPE["BinXmlTokenCloseEmptyElementTag"]
            value_text = b""

        if node_2nd_element.attrib:
            token_start = TOKEN_TYPE["BinXmlTokenOpenStartElementTag_Attribute"]
            event_details_data += _create_attribute_chunk(node_2nd_element.attrib)
            event_details_data += value_text
            event_details_data += pack("B", token_close)
            event_details += _element_start(event_details_data, token_start)
        else:
            token_start = TOKEN_TYPE["BinXmlTokenOpenStartElementTag_noAttribute"]
            event_details_data += value_text
            event_details_data += pack("B", token_close)
            event_details += _element_start(event_details_data, token_start)
    return event_details


def _process_nodes(node: etree._Element) -> bytes:
    binxml_chunk = b""
    for node_1st_element in node:
        event_details = _create_event_details(node_1st_element)
        binxml_1st_chunk = _create_name_chunk(node_1st_element.tag)
        binxml_1st_chunk += pack("B", TOKEN_TYPE["BinXmlTokenCloseStartElementTag"])
        binxml_chunk += _element_start(
            binxml_1st_chunk + event_details,
            TOKEN_TYPE["BinXmlTokenOpenStartElementTag_noAttribute"],
        )
        binxml_chunk += pack("B", TOKEN_TYPE["BinXmlTokenEndElementTag"])
    return binxml_chunk


def _convert_xml_to_binxml(node: etree._Element, event_number: int) -> bytes:
    binxml_chunk = _process_nodes(node)
    binxml_event = _create_name_chunk("Event")
    binxml_event += _create_attribute_chunk(
        {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
    )
    binxml_event += pack("B", TOKEN_TYPE["BinXmlTokenCloseStartElementTag"])
    binxml = _element_start(
        binxml_event + binxml_chunk,
        TOKEN_TYPE["BinXmlTokenOpenStartElementTag_Attribute"],
    )
    binxml += pack("B", TOKEN_TYPE["BinXmlTokenEndElementTag"])
    return _create_event_record(binxml + pack("B", TOKEN_TYPE["BinXmlTokenEOF"]), event_number)


def _element_start(data: bytes, token_start: int) -> bytes:
    element_header = b""
    for key, value in BINXML_ELEMENT_START.items():
        format_specifier, data_value = value
        if key == "open_start_element_tag_token":
            data_value = token_start
        elif key == "data_size":
            data_value = len(data) + 4
        element_header += pack(format_specifier, data_value)
    return element_header + data


def _create_name_chunk(name_element: str) -> bytes:
    binxml_name_data = b""
    for key, value in BINXML_NAME.items():
        format_specifier, data_value = value
        if key == "name_hash":
            data_value = _calc_name_hash(name_element)
        elif key == "number_of_characters":
            data_value = len(name_element)
        binxml_name_data += pack(format_specifier, data_value)
    binxml_name_data += _to_wordpack(name_element)
    binxml_name_data += pack("H", 0)
    return binxml_name_data


def _create_value_chunk(value_element: str) -> bytes:
    binxml_value_text_data = b""
    for key, value in BINXML_VALUE_TEXT.items():
        format_specifier, data_value = value
        if key == "data_size":
            data_value = len(value_element)
        binxml_value_text_data += pack(format_specifier, data_value)
    binxml_value_text_data += _to_wordpack(value_element)
    return binxml_value_text_data


def _create_attribute_chunk(attribute_element_dict: dict[str, str]) -> bytes:
    binxml_attribute_data = b""
    items = list(attribute_element_dict.items())
    for count, (attribute_name, attribute_value) in enumerate(items):
        attribute_token = (
            TOKEN_TYPE["BinXmlTokenAttribute"]
            if count == len(items) - 1
            else TOKEN_TYPE["BinXmlTokenAttribute_Next"]
        )
        for key, value in BINXML_ATTRIBUTE.items():
            format_specifier, data_value = value
            if key == "attribute_token":
                data_value = attribute_token
            binxml_attribute_data += pack(format_specifier, data_value)
        binxml_attribute_data += _create_name_chunk(attribute_name)
        binxml_attribute_data += _create_value_chunk(attribute_value)
    return pack("I", len(binxml_attribute_data)) + binxml_attribute_data


def _create_evtx(data: bytes, event_count: int, chunk_count: int) -> bytes:
    evtx_header = b""
    for key, value in EVTX_HEADER.items():
        format_specifier, data_value = value
        if key == "next_record_identifier":
            data_value = START_EVENT_RECORD_ID + event_count
        elif key == "last_chunk_number":
            data_value = chunk_count
        elif key == "number_of_chunks":
            data_value = chunk_count + 1
        elif key == "checksum":
            data_value = zlib.crc32(evtx_header[:120])
        evtx_header += pack(format_specifier, data_value)
    return evtx_header + data


def _create_evtx_chunk(data: bytes, event_count: int) -> bytes:
    evtx_chunk_header = b""
    last_event_record_number = START_EVENT_RECORD_ID + event_count - 1
    free_space_offset = len(data) + 0x0200
    common_string_offset = pack("12s", b"\x00") + pack("H", 0) + pack("370s", b"\x00")
    for key, value in EVTX_CHUNK_HEADER.items():
        format_specifier, data_value = value
        if key == "last_event_record_number":
            data_value = event_count
        elif key == "last_event_record_identifier":
            data_value = last_event_record_number
        elif key == "free_space_offset":
            data_value = free_space_offset
        elif key == "event_records_checksum":
            data_value = zlib.crc32(data)
        elif key == "checksum":
            data_value = zlib.crc32(evtx_chunk_header[:120] + common_string_offset)
        evtx_chunk_header += pack(format_specifier, data_value)
    return evtx_chunk_header + common_string_offset + data


def _create_chunk(binxml: bytes, total_event_count: int, total_chunk_count: int) -> bytearray:
    binxml_array = _fix_binxml_offset(binxml)
    evtx_chunk_part = _create_evtx_chunk(binxml_array, total_event_count)
    set_blank_len = MAX_CHUNK_SIZE - len(evtx_chunk_part)
    evtx_chunk_part += pack(f"{set_blank_len}s", b"\x00")

    evtx_chunk_array = bytearray(evtx_chunk_part)
    pattern = rb"\x2a\x2a\x00\x00"
    last_match = None
    for result in re.finditer(pattern, evtx_chunk_part):
        last_match = result
    if last_match is None:
        msg = "Failed to locate EVTX record header in chunk"
        raise ValueError(msg)
    offset = pack("I", last_match.start())
    for index in range(4):
        evtx_chunk_array[0x2C + index] = offset[index]

    evtx_chunk_hash = pack("I", zlib.crc32(evtx_chunk_array[:120] + evtx_chunk_array[128:512]))
    for index in range(4):
        evtx_chunk_array[124 + index] = evtx_chunk_hash[index]
    logger.debug("finished chunk %s", total_chunk_count)
    return evtx_chunk_array


def _fix_binxml_offset(binxml: bytes) -> bytearray:
    binxml_array = bytearray(binxml)
    for pattern in (re.compile(rb"\x99\x99\x99\x99"), re.compile(rb"\x88\x88\x88\x88")):
        for result in pattern.finditer(binxml):
            offset = pack("I", result.start() + 0x204)
            for index in range(4):
                binxml_array[result.start() + index] = offset[index]
    return binxml_array


def _create_event_record(data: bytes, count: int) -> bytes:
    event_record = b""
    for key, value in EVTX_EVENT_RECORD_HEADER.items():
        format_specifier, data_value = value
        if key == "size":
            data_value = len(data) + 0x20
        elif key == "identifier":
            data_value = START_EVENT_RECORD_ID + count - 1
        elif key == "written_time":
            data_value = _getnttime(datetime.now())
        event_record += pack(format_specifier, data_value)
    event_record += pack(">I", FLAGMENT_HEADER)
    return event_record + data + pack("I", len(data) + 0x20)


def _process_xml_text(xml_text: str) -> tuple[int, int, bytes]:
    total_chunk_count = 0
    total_event_count = 0
    binxml = b""
    evtx_chunk = b""
    for node, err in iter_xml_record_nodes(xml_text):
        if err is not None:
            logger.error("Skipping invalid XML event: %s", err)
            continue
        total_event_count += 1
        part_of_binxml = _convert_xml_to_binxml(node, total_event_count)
        if len(binxml + part_of_binxml) > MAX_CHUNK_SIZE - 0x200:
            evtx_chunk += _create_chunk(binxml, total_event_count, total_chunk_count)
            binxml = part_of_binxml
            total_chunk_count += 1
        else:
            binxml += part_of_binxml
    evtx_chunk += _create_chunk(binxml, total_event_count, total_chunk_count)
    return total_event_count, total_chunk_count, evtx_chunk
