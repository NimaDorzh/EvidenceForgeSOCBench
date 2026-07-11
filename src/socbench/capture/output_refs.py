"""Resolve canonical events to concrete records under bundle data/."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from socbench.capture.models import CanonicalEvent

_FORMAT_FILENAMES: dict[str, tuple[str, ...]] = {
    "zeek_conn": ("conn.json",),
    "zeek_dns": ("dns.json",),
    "windows_event_sysmon": ("windows_event_sysmon.xml",),
    "windows_event_security": ("windows_event_security.xml",),
    "ecar": ("ecar.json",),
    "syslog": ("syslog.log",),
    "bash_history": ("bash_history.log",),
    "proxy_access": ("proxy_access.log",),
    "web_access": ("web_access.log",),
    "cisco_asa": ("cisco_asa.log",),
    "snort_alert": ("snort_alert.log",),
}


def resolve_output_refs(
    event: CanonicalEvent,
    data_root: Path,
    observed_formats: list[str],
) -> dict[str, str]:
    """Best-effort mapping from a canonical event to data/ record anchors."""
    refs: dict[str, str] = {}
    fields = event.fields
    host_dirs = _host_directories(data_root, event.host)

    for fmt in observed_formats:
        if fmt in refs:
            continue
        filenames = _FORMAT_FILENAMES.get(fmt, ())
        candidates = _candidate_files(data_root, host_dirs, filenames)
        if fmt == "zeek_conn":
            ref = _resolve_zeek_conn(candidates, fields)
        elif fmt in {"windows_event_sysmon", "windows_event_security"}:
            ref = _resolve_windows_xml(candidates, fields)
        elif fmt == "ecar":
            ref = _resolve_ecar_json(candidates, fields)
        elif fmt in {"proxy_access", "web_access", "cisco_asa", "snort_alert", "syslog"}:
            ref = _resolve_text_log(candidates, fields)
        elif fmt == "zeek_dns":
            ref = _resolve_zeek_dns(candidates, fields)
        else:
            ref = None
        if ref is not None:
            refs[fmt] = ref
    return refs


def _candidate_files(
    data_root: Path,
    host_dirs: list[Path],
    filenames: tuple[str, ...],
) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    search_roots = host_dirs + [data_root]
    for root in search_roots:
        if not root.exists():
            continue
        for filename in filenames:
            for path in root.rglob(filename):
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                paths.append(path)
    return paths


def _host_directories(data_root: Path, hostname: str) -> list[Path]:
    if not data_root.is_dir():
        return []
    needle = hostname.lower()
    return sorted(
        path for path in data_root.iterdir() if path.is_dir() and needle in path.name.lower()
    )


def _relative_ref(path: Path, data_root: Path, anchor: str) -> str:
    rel = path.relative_to(data_root.parent).as_posix()
    return f"{rel}{anchor}"


def _resolve_zeek_conn(paths: list[Path], fields: dict[str, Any]) -> str | None:
    uid = fields.get("uid")
    if isinstance(uid, str):
        for path in paths:
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if uid in line:
                    return _relative_ref(path, path.parent.parent, f"#L{line_no}")
    dst_ip = fields.get("dst_ip")
    dst_port = fields.get("dst_port")
    if dst_ip is not None and dst_port is not None:
        needle = f'"id.resp_h":"{dst_ip}","id.resp_p":{dst_port}'
        for path in paths:
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if needle in line:
                    return _relative_ref(path, path.parent.parent, f"#L{line_no}")
    return None


def _resolve_zeek_dns(paths: list[Path], fields: dict[str, Any]) -> str | None:
    query = fields.get("query")
    if not isinstance(query, str):
        return None
    for path in paths:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if query in line:
                return _relative_ref(path, path.parent.parent, f"#L{line_no}")
    return None


def _resolve_windows_xml(paths: list[Path], fields: dict[str, Any]) -> str | None:
    needles: list[str] = []
    command_line = fields.get("command_line")
    if isinstance(command_line, str) and command_line:
        needles.append(command_line)
    pid = fields.get("pid")
    if isinstance(pid, int):
        needles.append(f'<Data Name="ProcessId">{pid}</Data>')
    if not needles:
        return None
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            idx = text.find(needle)
            if idx < 0:
                continue
            record_no = text[:idx].count("<Event ") + text[:idx].count("<Event\n")
            return _relative_ref(path, path.parent.parent, f"#rec{record_no}")
    return None


def _resolve_ecar_json(paths: list[Path], fields: dict[str, Any]) -> str | None:
    needles: list[str] = []
    command_line = fields.get("command_line")
    if isinstance(command_line, str) and command_line:
        needles.append(command_line)
    uid = fields.get("uid")
    if isinstance(uid, str):
        needles.append(uid)
    dst_ip = fields.get("dst_ip")
    if isinstance(dst_ip, str):
        needles.append(dst_ip)
    if not needles:
        return None
    for path in paths:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if any(needle in line for needle in needles):
                return _relative_ref(path, path.parent.parent, f"#L{line_no}")
    return None


def _resolve_text_log(paths: list[Path], fields: dict[str, Any]) -> str | None:
    needles: list[str] = []
    for key in ("command_line", "dst_ip", "query", "uid"):
        value = fields.get(key)
        if isinstance(value, str) and value:
            needles.append(value)
    if not needles:
        return None
    for path in paths:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if any(needle in line for needle in needles):
                return _relative_ref(path, path.parent.parent, f"#L{line_no}")
    return None
