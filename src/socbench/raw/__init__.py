"""Native host-log binary conversion for SOC-bench."""

from __future__ import annotations

from socbench.raw.evtx import (
    chainsaw_available,
    compare_event_field_sets,
    convert_xml_file_to_evtx,
    convert_xml_text_to_evtx,
    parse_evtx_event_fields,
    parse_xml_event_fields,
)
from socbench.raw.host_logs import (
    HostLogConvertResult,
    bucketize_host_logs,
    convert_staged_host_logs,
    copy_ef_host_logs,
    discover_host_log_files,
)
from socbench.raw.journal import (
    compare_syslog_journal_records,
    convert_syslog_file_to_journal,
    docker_available,
    parse_journal_fields,
    parse_syslog_lines,
    wsl_journal_remote_available,
)

__all__ = [
    "HostLogConvertResult",
    "bucketize_host_logs",
    "chainsaw_available",
    "compare_event_field_sets",
    "compare_syslog_journal_records",
    "convert_staged_host_logs",
    "convert_syslog_file_to_journal",
    "convert_xml_file_to_evtx",
    "convert_xml_text_to_evtx",
    "copy_ef_host_logs",
    "discover_host_log_files",
    "docker_available",
    "parse_evtx_event_fields",
    "parse_journal_fields",
    "parse_syslog_lines",
    "parse_xml_event_fields",
    "wsl_journal_remote_available",
]
