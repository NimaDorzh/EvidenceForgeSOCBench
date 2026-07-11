"""Resolve canonical events to concrete records under bundle data/."""

from __future__ import annotations

import json
import re
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

# Endpoint formats must not search the whole data/ tree (PID collisions across hosts).
_HOST_SCOPED_FORMATS = frozenset(
    {
        "windows_event_sysmon",
        "windows_event_security",
        "ecar",
        "syslog",
        "bash_history",
    }
)

_XML_EVENT_SPLIT = re.compile(r"(?=<Event[\s>])")
_XML_DATA_FIELD = re.compile(r'<Data Name="([^"]+)">([^<]*)</Data>')
_XML_EVENT_ID = re.compile(r"<EventID>(\d+)</EventID>")


def resolve_output_refs(
    event: CanonicalEvent,
    data_root: Path,
    observed_formats: list[str],
) -> dict[str, str]:
    """Map candidate formats to data/ anchors only when fields confirm the row.

    Unmatched formats are omitted (no #L1 / first-line fallback). Callers that
    need symmetry must treat missing refs as unresolved after this honest attempt.
    """
    refs: dict[str, str] = {}
    fields = event.fields
    kind = event.kind
    host_dirs = _host_directories(data_root, event.host)
    bundle_root = data_root.parent

    for fmt in observed_formats:
        if fmt in refs:
            continue
        filenames = _FORMAT_FILENAMES.get(fmt, ())
        if fmt in _HOST_SCOPED_FORMATS and not host_dirs:
            continue
        search_hosts = host_dirs if fmt in _HOST_SCOPED_FORMATS else host_dirs
        include_data_root = fmt not in _HOST_SCOPED_FORMATS
        candidates = _candidate_files(
            data_root,
            search_hosts,
            filenames,
            include_data_root=include_data_root,
        )
        if fmt == "zeek_conn":
            ref = _resolve_zeek_conn(candidates, fields, bundle_root)
        elif fmt == "zeek_dns":
            ref = _resolve_zeek_dns(candidates, fields, bundle_root)
        elif fmt in {"windows_event_sysmon", "windows_event_security"}:
            ref = _resolve_windows_xml(candidates, fields, bundle_root, kind=kind, fmt=fmt)
        elif fmt == "ecar":
            ref = _resolve_ecar_json(candidates, fields, bundle_root, kind=kind)
        elif fmt == "web_access":
            ref = _resolve_web_access(candidates, fields, bundle_root)
        elif fmt == "proxy_access":
            ref = _resolve_proxy_access(candidates, fields, bundle_root)
        elif fmt == "cisco_asa":
            ref = _resolve_cisco_asa(candidates, fields, bundle_root, kind=kind)
        elif fmt in {"snort_alert", "syslog", "bash_history"}:
            ref = _resolve_text_log(candidates, fields, bundle_root, kind=kind, fmt=fmt)
        else:
            ref = None
        if ref is not None:
            refs[fmt] = ref
    return refs


def _candidate_files(
    data_root: Path,
    host_dirs: list[Path],
    filenames: tuple[str, ...],
    *,
    include_data_root: bool = True,
) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    search_roots = list(host_dirs)
    if include_data_root:
        search_roots.append(data_root)
    for root in search_roots:
        if not root.exists():
            continue
        for filename in filenames:
            for path in sorted(root.rglob(filename)):
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


def _relative_ref(path: Path, bundle_root: Path, anchor: str) -> str:
    rel = path.relative_to(bundle_root).as_posix()
    return f"{rel}{anchor}"


def _iter_xml_events(text: str) -> list[str]:
    return [chunk for chunk in _XML_EVENT_SPLIT.split(text) if chunk.strip().startswith("<Event")]


def _xml_event_id(chunk: str) -> int | None:
    match = _XML_EVENT_ID.search(chunk)
    return int(match.group(1)) if match else None


def _xml_data_fields(chunk: str) -> dict[str, str]:
    return {name: value for name, value in _XML_DATA_FIELD.findall(chunk)}


def _normalize_ip(value: Any) -> str:
    raw = str(value).strip().lower()
    if raw.startswith("::ffff:"):
        raw = raw.removeprefix("::ffff:")
    return raw


def _normalize_logon_id(value: Any) -> str:
    raw = str(value).strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        return format(int(raw, 16), "x")
    except ValueError:
        return raw


def _field_values_match(
    fields: dict[str, Any],
    present: dict[str, str],
    *,
    normalizers: dict[str, Any] | None = None,
) -> bool:
    """Return True when every key in *fields* that appears in *present* matches."""
    normalizers = normalizers or {}
    matched_any = False
    for field_key, actual_value in present.items():
        if field_key not in fields:
            continue
        expected = fields[field_key]
        if expected is None or expected == "":
            continue
        matched_any = True
        normalize = normalizers.get(field_key)
        left = normalize(expected) if normalize else str(expected)
        right = normalize(actual_value) if normalize else str(actual_value)
        if left != right:
            return False
    return matched_any


def _match_logon_security(chunk: str, fields: dict[str, Any]) -> bool:
    event_id = _xml_event_id(chunk)
    if event_id not in {4624, 4625}:
        return False
    data = _xml_data_fields(chunk)
    present = {
        "logon_id": data.get("TargetLogonId", ""),
        "source_ip": data.get("IpAddress", ""),
        "logon_type": data.get("LogonType", ""),
    }
    return _field_values_match(
        fields,
        present,
        normalizers={
            "logon_id": _normalize_logon_id,
            "logon_type": str,
            "source_ip": _normalize_ip,
        },
    )


def _match_explicit_credentials_security(chunk: str, fields: dict[str, Any]) -> bool:
    if _xml_event_id(chunk) != 4648:
        return False
    data = _xml_data_fields(chunk)
    target_username = fields.get("target_username")
    if not isinstance(target_username, str) or not target_username:
        return False
    xml_user = data.get("TargetUserName", "")
    xml_domain = data.get("TargetDomainName", "")
    expected_lower = target_username.lower()
    bare_expected = expected_lower.split("\\")[-1]
    full_xml = f"{xml_domain}\\{xml_user}".lower() if xml_domain and xml_user else xml_user.lower()
    return (
        xml_user.lower() == expected_lower
        or full_xml == expected_lower
        or xml_user.lower() == bare_expected
    )


def _match_service_installed_security(chunk: str, fields: dict[str, Any]) -> bool:
    if _xml_event_id(chunk) != 4697:
        return False
    service_name = fields.get("service_name")
    if not isinstance(service_name, str) or not service_name:
        return False
    data = _xml_data_fields(chunk)
    return data.get("ServiceName", "") == service_name


def _match_create_remote_thread_sysmon(chunk: str, fields: dict[str, Any]) -> bool:
    if _xml_event_id(chunk) != 8:
        return False
    target_process = fields.get("target_process")
    if not isinstance(target_process, str) or not target_process:
        return False
    data = _xml_data_fields(chunk)
    target_image = data.get("TargetImage", "")
    if target_image == target_process:
        return True
    return target_image.lower().endswith(target_process.split("\\")[-1].lower())


def _zeek_conn_for_uid(data_root: Path, uid: str) -> dict[str, Any] | None:
    needle = f'"uid":"{uid}"'
    for path in sorted(data_root.rglob("conn.json")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if needle not in line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            return {
                "orig_h": record.get("id.orig_h"),
                "orig_p": record.get("id.orig_p"),
                "resp_h": record.get("id.resp_h"),
                "resp_p": record.get("id.resp_p"),
                "service": record.get("service"),
            }
    return None


def _match_rdp_session_security(
    chunk: str,
    fields: dict[str, Any],
    *,
    data_root: Path | None,
) -> bool:
    if _xml_event_id(chunk) != 4624:
        return False
    data = _xml_data_fields(chunk)
    if data.get("LogonType") != "10":
        return False
    present = {
        "logon_id": data.get("TargetLogonId", ""),
        "source_ip": data.get("IpAddress", ""),
    }
    if _field_values_match(
        fields,
        present,
        normalizers={"logon_id": _normalize_logon_id, "source_ip": _normalize_ip},
    ):
        return True
    uid = fields.get("uid")
    if not isinstance(uid, str) or not uid or uid.startswith("(filtered") or data_root is None:
        return False
    zeek = _zeek_conn_for_uid(data_root, uid)
    if zeek is None:
        return False
    dst_port = fields.get("dst_port")
    if dst_port is not None and zeek.get("resp_p") != dst_port:
        return False
    dst_ip = fields.get("dst_ip")
    if isinstance(dst_ip, str) and zeek.get("resp_h") and zeek["resp_h"] != dst_ip:
        return False
    orig_h = zeek.get("orig_h")
    if isinstance(orig_h, str) and _normalize_ip(data.get("IpAddress", "")) == _normalize_ip(orig_h):
        return True
    return False


def _match_ecar_rdp_session(record: dict[str, Any], fields: dict[str, Any]) -> bool:
    return _match_ecar_flow(record, fields)


def _resolve_zeek_conn(
    paths: list[Path],
    fields: dict[str, Any],
    bundle_root: Path,
) -> str | None:
    uid = fields.get("uid")
    if isinstance(uid, str) and uid and not uid.startswith("(filtered"):
        for path in paths:
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if uid in line:
                    return _relative_ref(path, bundle_root, f"#L{line_no}")
    dst_ip = fields.get("dst_ip")
    dst_port = fields.get("dst_port")
    if isinstance(dst_ip, str) and dst_port is not None:
        needle = f'"id.resp_h":"{dst_ip}","id.resp_p":{dst_port}'
        for path in paths:
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if needle in line:
                    return _relative_ref(path, bundle_root, f"#L{line_no}")
    return None


def _resolve_zeek_dns(
    paths: list[Path],
    fields: dict[str, Any],
    bundle_root: Path,
) -> str | None:
    query = fields.get("query")
    if not isinstance(query, str) or not query:
        return None
    for path in paths:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if query in line:
                return _relative_ref(path, bundle_root, f"#L{line_no}")
    return None


def _resolve_windows_xml(
    paths: list[Path],
    fields: dict[str, Any],
    bundle_root: Path,
    *,
    kind: str,
    fmt: str,
) -> str | None:
    kind_matchers: dict[str, Any] = {}
    data_root = bundle_root / "data"
    if fmt == "windows_event_security":
        kind_matchers = {
            "logon": _match_logon_security,
            "explicit_credentials": _match_explicit_credentials_security,
            "service_installed": _match_service_installed_security,
            "rdp_session": lambda chunk, field_values: _match_rdp_session_security(
                chunk,
                field_values,
                data_root=data_root,
            ),
        }
    elif fmt == "windows_event_sysmon":
        kind_matchers = {
            "create_remote_thread": _match_create_remote_thread_sysmon,
        }

    matcher = kind_matchers.get(kind)
    if matcher is not None:
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for record_no, chunk in enumerate(_iter_xml_events(text), start=1):
                if matcher(chunk, fields):
                    return _relative_ref(path, bundle_root, f"#rec{record_no}")

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
            if record_no < 1:
                continue
            return _relative_ref(path, bundle_root, f"#rec{record_no}")
    return None


def _parse_ecar_record(line: str) -> dict[str, Any] | None:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _ecar_get(record: dict[str, Any], key: str) -> Any:
    value = record.get(key)
    if value not in (None, ""):
        return value
    properties = record.get("properties")
    if isinstance(properties, dict):
        return properties.get(key, "")
    return ""


def _ecar_string(value: Any) -> str:
    return str(value)


def _ecar_flow_present(record: dict[str, Any], fields: dict[str, Any]) -> dict[str, str]:
    present: dict[str, str] = {}
    for key in ("source_ip", "dst_ip", "dst_port"):
        if key not in fields:
            continue
        ecar_key = "src_ip" if key == "source_ip" else key
        present[key] = _ecar_string(_ecar_get(record, ecar_key))
    return present


def _match_ecar_logon(record: dict[str, Any], fields: dict[str, Any]) -> bool:
    if record.get("object") != "USER_SESSION" or record.get("action") != "LOGIN":
        return False
    present = {
        "source_ip": _ecar_string(_ecar_get(record, "src_ip")),
        "logon_type": _ecar_string(_ecar_get(record, "logon_type")),
        "logon_id": _ecar_string(_ecar_get(record, "logon_id")),
    }
    return _field_values_match(
        fields,
        present,
        normalizers={
            "logon_id": _normalize_logon_id,
            "logon_type": str,
            "source_ip": _normalize_ip,
        },
    )


def _match_ecar_service_installed(record: dict[str, Any], fields: dict[str, Any]) -> bool:
    if record.get("object") != "SERVICE" or record.get("action") != "CREATE":
        return False
    service_name = fields.get("service_name")
    if not isinstance(service_name, str) or not service_name:
        return False
    return _ecar_string(_ecar_get(record, "service_name")) == service_name


def _match_ecar_create_remote_thread(
    record: dict[str, Any],
    fields: dict[str, Any],
    *,
    pid_images: dict[str, str] | None = None,
) -> bool:
    if record.get("object") != "THREAD" or record.get("action") != "REMOTE_CREATE":
        return False
    target_process = fields.get("target_process")
    if not isinstance(target_process, str) or not target_process:
        return False
    target_name = target_process.split("\\")[-1].lower()
    image_path = _ecar_string(_ecar_get(record, "image_path")).lower()
    target_image = _ecar_string(_ecar_get(record, "target_image")).lower()
    if target_name and (
        target_name in image_path
        or target_name in target_image
        or target_name in json.dumps(record, sort_keys=True).lower()
    ):
        return True
    target_pid = _ecar_string(_ecar_get(record, "target_pid"))
    if target_name and target_pid and pid_images:
        proc_image = pid_images.get(target_pid, "")
        if target_name in proc_image:
            return True
    return False


def _match_ecar_flow(record: dict[str, Any], fields: dict[str, Any]) -> bool:
    if record.get("object") != "FLOW":
        return False
    present = _ecar_flow_present(record, fields)
    return _field_values_match(
        fields, present, normalizers={"dst_port": str, "source_ip": _normalize_ip}
    )


def _match_ecar_ssh_session(record: dict[str, Any], fields: dict[str, Any]) -> bool:
    if record.get("object") == "FLOW":
        return _match_ecar_flow(record, fields)
    if record.get("object") != "USER_SESSION" or record.get("action") != "LOGIN":
        return False
    session_type = _ecar_string(_ecar_get(record, "session_type")).lower()
    if session_type and session_type != "ssh":
        return False
    present = {"source_ip": _ecar_string(_ecar_get(record, "src_ip"))}
    if "dst_ip" in fields or "dst_port" in fields:
        return False
    return _field_values_match(fields, present, normalizers={"source_ip": _normalize_ip})


def _resolve_ecar_json(
    paths: list[Path],
    fields: dict[str, Any],
    bundle_root: Path,
    *,
    kind: str,
) -> str | None:
    kind_matchers = {
        "logon": _match_ecar_logon,
        "service_installed": _match_ecar_service_installed,
        "create_remote_thread": _match_ecar_create_remote_thread,
        "connection": _match_ecar_flow,
        "ssh_session": _match_ecar_ssh_session,
        "rdp_session": _match_ecar_rdp_session,
    }
    matcher = kind_matchers.get(kind)
    if matcher is not None:
        for path in paths:
            lines = path.read_text(encoding="utf-8").splitlines()
            pid_images: dict[str, str] = {}
            if kind == "create_remote_thread":
                for line in lines:
                    record = _parse_ecar_record(line)
                    if record is None or record.get("object") != "PROCESS":
                        continue
                    if record.get("action") != "CREATE":
                        continue
                    pid = record.get("pid")
                    if pid is None:
                        continue
                    pid_images[str(pid)] = _ecar_string(_ecar_get(record, "image_path")).lower()
            for line_no, line in enumerate(lines, start=1):
                record = _parse_ecar_record(line)
                if record is None:
                    continue
                matched = (
                    matcher(record, fields, pid_images=pid_images)
                    if kind == "create_remote_thread"
                    else matcher(record, fields)
                )
                if matched:
                    return _relative_ref(path, bundle_root, f"#L{line_no}")

    strong: list[str] = []
    command_line = fields.get("command_line")
    if isinstance(command_line, str) and len(command_line) >= 4:
        strong.append(command_line)
    uid = fields.get("uid")
    if isinstance(uid, str) and uid and not uid.startswith("(filtered"):
        strong.append(uid)
    pid = fields.get("pid")
    if isinstance(pid, int):
        strong.append(f'"pid":{pid}')
    if not strong:
        return None
    for path in paths:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if any(needle in line for needle in strong):
                return _relative_ref(path, bundle_root, f"#L{line_no}")
    return None


def _resolve_web_access(
    paths: list[Path],
    fields: dict[str, Any],
    bundle_root: Path,
) -> str | None:
    needles = _network_needles(fields)
    preset = fields.get("preset")
    if isinstance(preset, str) and preset:
        needles.append(preset)
    return _first_line_with_needles(paths, needles, bundle_root)


def _resolve_proxy_access(
    paths: list[Path],
    fields: dict[str, Any],
    bundle_root: Path,
) -> str | None:
    return _first_line_with_needles(paths, _network_needles(fields), bundle_root)


def _asa_connection_line_matches(line: str, dst_ip: str, dst_port: int) -> bool:
    if dst_ip not in line:
        return False
    port_tokens = (
        f"/{dst_port}",
        f":{dst_port}",
        f"DPT={dst_port}",
        f"/{dst_port} ",
        f"/{dst_port},",
    )
    if any(token in line for token in port_tokens):
        return True
    if f"{dst_ip}/{dst_port}" in line:
        return True
    return False


def _zeek_resp_port_for_uid(data_root: Path, uid: str, dst_ip: str | None = None) -> int | None:
    needle = f'"uid":"{uid}"'
    for path in sorted(data_root.rglob("conn.json")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if needle not in line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            resp_h = record.get("id.resp_h")
            resp_p = record.get("id.resp_p")
            if resp_p is None:
                continue
            if isinstance(dst_ip, str) and resp_h and resp_h != dst_ip:
                continue
            return int(resp_p)
    return None


def _resolve_cisco_asa(
    paths: list[Path],
    fields: dict[str, Any],
    bundle_root: Path,
    *,
    kind: str,
) -> str | None:
    dst_ip = fields.get("dst_ip")
    dst_port = fields.get("dst_port")
    if isinstance(dst_ip, str) and dst_port is not None:
        ports = [int(dst_port)]
        uid = fields.get("uid")
        if isinstance(uid, str) and uid and not uid.startswith("(filtered"):
            zeek_port = _zeek_resp_port_for_uid(bundle_root / "data", uid, dst_ip)
            if zeek_port is not None and zeek_port not in ports:
                ports.append(zeek_port)
        for path in paths:
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if any(_asa_connection_line_matches(line, dst_ip, port) for port in ports):
                    return _relative_ref(path, bundle_root, f"#L{line_no}")

    needles: list[str] = []
    command_line = fields.get("command_line")
    if isinstance(command_line, str) and len(command_line) >= 4:
        needles.append(command_line)
    uid = fields.get("uid")
    if isinstance(uid, str) and uid and not uid.startswith("(filtered"):
        needles.append(uid)
    return _first_line_with_needles(paths, needles, bundle_root)


def _resolve_text_log(
    paths: list[Path],
    fields: dict[str, Any],
    bundle_root: Path,
    *,
    kind: str,
    fmt: str,
) -> str | None:
    if fmt == "syslog" and kind == "ssh_session":
        user = fields.get("user") or fields.get("actor")
        source_ip = fields.get("source_ip")
        for path in paths:
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if "sshd" not in line:
                    continue
                if "Accepted" not in line and "Opened" not in line and "session opened" not in line:
                    continue
                if isinstance(user, str) and user and user not in line:
                    continue
                if isinstance(source_ip, str) and source_ip and source_ip not in line:
                    continue
                return _relative_ref(path, bundle_root, f"#L{line_no}")

    needles: list[str] = []
    command_line = fields.get("command_line")
    if isinstance(command_line, str) and len(command_line) >= 4:
        needles.append(command_line)
    uid = fields.get("uid")
    if isinstance(uid, str) and uid and not uid.startswith("(filtered"):
        needles.append(uid)
    dst_ip = fields.get("dst_ip")
    dst_port = fields.get("dst_port")
    if isinstance(dst_ip, str) and dst_port is not None:
        for path in paths:
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if _asa_connection_line_matches(line, dst_ip, int(dst_port)):
                    return _relative_ref(path, bundle_root, f"#L{line_no}")
    return _first_line_with_needles(paths, needles, bundle_root)


def _network_needles(fields: dict[str, Any]) -> list[str]:
    needles: list[str] = []
    for key in ("uid", "query", "command_line"):
        value = fields.get(key)
        if isinstance(value, str) and value:
            needles.append(value)
    dst_ip = fields.get("dst_ip")
    if isinstance(dst_ip, str) and dst_ip:
        needles.append(dst_ip)
    return needles


def _first_line_with_needles(
    paths: list[Path],
    needles: list[str],
    bundle_root: Path,
) -> str | None:
    if not needles:
        return None
    for path in paths:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if any(needle in line for needle in needles):
                return _relative_ref(path, bundle_root, f"#L{line_no}")
    return None
