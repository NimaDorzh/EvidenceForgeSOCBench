"""RFC5424 syslog to native systemd journal conversion."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from socbench.raw.errors import JournalBackendUnavailableError, JournalConversionError

logger = logging.getLogger(__name__)

_SYSLOG_LINE_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured>-|[^\s]+)\s+"
    r"(?P<message>.*)$"
)

_JOURNAL_DOCKER_IMAGE = "quay.io/fedora/fedora:40"
_JOURNAL_REMOTE_SHELL_RESOLVE = (
    "JR=$(command -v systemd-journal-remote 2>/dev/null || true); "
    'if [ -z "$JR" ] && [ -x /usr/lib/systemd/systemd-journal-remote ]; then '
    "JR=/usr/lib/systemd/systemd-journal-remote; fi; "
    'if [ -z "$JR" ] && [ -x /lib/systemd/systemd-journal-remote ]; then '
    "JR=/lib/systemd/systemd-journal-remote; fi; "
    'if [ -z "$JR" ]; then echo "systemd-journal-remote not found" >&2; exit 127; fi'
)


def parse_syslog_lines(syslog_text: str) -> list[dict[str, str]]:
    """Parse RFC5424 syslog lines into comparable field dictionaries."""
    records: list[dict[str, str]] = []
    for line_no, raw_line in enumerate(syslog_text.splitlines(), start=1):
        line = raw_line.strip().strip("\r")
        if not line:
            continue
        match = _SYSLOG_LINE_RE.match(line)
        if match is None:
            msg = f"Invalid RFC5424 syslog at line {line_no}: {line[:120]!r}"
            raise JournalConversionError(msg)
        pri_int = int(match.group("pri"))
        records.append(
            {
                "priority": str(pri_int % 8),
                "facility": str(pri_int // 8),
                "timestamp": match.group("timestamp"),
                "hostname": match.group("hostname"),
                "appname": match.group("appname"),
                "procid": match.group("procid"),
                "msgid": match.group("msgid"),
                "message": match.group("message"),
            }
        )
    return records


def convert_syslog_file_to_journal(syslog_path: Path, journal_path: Path) -> int:
    """Convert an RFC5424 ``syslog.log`` file to a native ``.journal`` file."""
    syslog_path = syslog_path.resolve()
    journal_path = journal_path.resolve()
    records = parse_syslog_lines(syslog_path.read_text(encoding="utf-8"))
    if not records:
        msg = f"No RFC5424 syslog records found in {syslog_path}"
        raise JournalConversionError(msg)

    backend = _resolve_journal_backend()
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    export_path = journal_path.with_suffix(f"{journal_path.suffix}.export")
    try:
        _write_journal_export_file(records, export_path)
        if backend == "docker":
            _convert_export_with_docker(export_path, journal_path)
        else:
            _convert_export_with_wsl(export_path, journal_path)
    finally:
        export_path.unlink(missing_ok=True)
    return len(records)


def parse_journal_fields(journal_path: Path) -> list[dict[str, Any]]:
    """Read a journal file via ``journalctl --file`` and return comparable fields."""
    backend = _resolve_journal_backend(allow_missing=True)
    if backend == "docker":
        return _read_journal_with_docker(journal_path)
    if backend == "wsl":
        return _read_journal_with_wsl(journal_path)
    raise JournalBackendUnavailableError(
        "No journal backend available; start Docker Desktop or install "
        "systemd-journal-remote in WSL"
    )


def compare_syslog_journal_records(
    syslog_records: list[dict[str, str]],
    journal_records: list[dict[str, Any]],
) -> list[str]:
    """Return human-readable mismatches between syslog and journal field maps."""
    mismatches: list[str] = []
    if len(syslog_records) != len(journal_records):
        mismatches.append(
            f"record count mismatch: syslog={len(syslog_records)} journal={len(journal_records)}"
        )
    for index, source in enumerate(syslog_records):
        if index >= len(journal_records):
            break
        parsed = journal_records[index]
        for key in ("priority", "timestamp", "hostname", "appname", "message"):
            source_value = _normalize_compare_value(source.get(key, ""))
            parsed_value = _normalize_compare_value(parsed.get(key, ""))
            if source_value != parsed_value:
                mismatches.append(
                    f"record[{index}] field {key!r}: syslog={source.get(key)!r} "
                    f"journal={parsed.get(key)!r}"
                )
    return mismatches


def docker_available() -> bool:
    """Return True when the Docker CLI can reach a running daemon."""
    if shutil.which("docker") is None:
        return False
    proc = subprocess.run(
        ["docker", "info"],
        check=False,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def wsl_journal_remote_available() -> bool:
    """Return True when WSL exposes ``systemd-journal-remote``."""
    if shutil.which("wsl") is None:
        return False
    proc = subprocess.run(
        [
            "wsl",
            "-e",
            "bash",
            "-lc",
            "command -v systemd-journal-remote >/dev/null 2>&1 || "
            "test -x /usr/lib/systemd/systemd-journal-remote || "
            "test -x /lib/systemd/systemd-journal-remote",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def _resolve_journal_backend(*, allow_missing: bool = False) -> str:
    if docker_available():
        return "docker"
    if wsl_journal_remote_available():
        return "wsl"
    if allow_missing:
        return "none"
    raise JournalBackendUnavailableError(
        "Journal conversion requires Docker (running daemon) or WSL with "
        "systemd-journal-remote installed"
    )


def _convert_export_with_docker(export_path: Path, journal_path: Path) -> None:
    work_dir = export_path.parent.resolve()
    mount = f"{work_dir}:/work"
    rel_export = export_path.name
    rel_journal = journal_path.name
    command = (
        "set -euo pipefail; "
        "dnf install -y -q systemd-journal-remote >/dev/null; "
        f"{_JOURNAL_REMOTE_SHELL_RESOLVE}; "
        f'"$JR" -o /work/{rel_journal} /work/{rel_export}'
    )
    proc = subprocess.run(
        ["docker", "run", "--rm", "-v", mount, _JOURNAL_DOCKER_IMAGE, "bash", "-lc", command],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not journal_path.is_file():
        raise JournalConversionError(
            "Docker journal conversion failed: "
            f"{proc.stderr.strip() or proc.stdout.strip() or proc.returncode}"
        )


def _convert_export_with_wsl(export_path: Path, journal_path: Path) -> None:
    win_export = str(export_path)
    win_journal = str(journal_path)
    command = (
        "set -euo pipefail; "
        f"{_JOURNAL_REMOTE_SHELL_RESOLVE}; "
        f'"$JR" -o \'{win_journal}\' \'{win_export}\''
    )
    proc = subprocess.run(
        ["wsl", "-e", "bash", "-lc", command],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not journal_path.is_file():
        raise JournalConversionError(
            "WSL journal conversion failed: "
            f"{proc.stderr.strip() or proc.stdout.strip() or proc.returncode}"
        )


def _write_journal_export_file(records: list[dict[str, str]], export_path: Path) -> None:
    """Render parsed RFC5424 records into systemd Journal Export Format."""
    boot_id = uuid.uuid4().hex
    entries: list[str] = []
    monotonic_base = 1_000_000
    for index, record in enumerate(records):
        usec = _rfc5424_timestamp_to_usec(record["timestamp"])
        severity = int(record["priority"])
        facility = int(record.get("facility", "0"))
        monotonic = monotonic_base + (index * 1_000)
        entry_fields = [
            f"__REALTIME_TIMESTAMP={usec}",
            f"__MONOTONIC_TIMESTAMP={monotonic}",
            f"_BOOT_ID={boot_id}",
            "_TRANSPORT=syslog",
            f"PRIORITY={severity}",
            f"SYSLOG_FACILITY={facility}",
            f"SYSLOG_IDENTIFIER={record['appname']}",
            f"MESSAGE={record['message']}",
            f"_SOURCE_REALTIME_TIMESTAMP={usec}",
            f"_HOSTNAME={record['hostname']}",
        ]
        procid = record.get("procid", "-")
        if procid not in {"", "-"}:
            entry_fields.append(f"SYSLOG_PID={procid}")
        entries.append("\n".join(entry_fields))
    export_path.write_text("\n\n".join(entries) + "\n\n", encoding="utf-8", newline="\n")


def _rfc5424_timestamp_to_usec(timestamp: str) -> int:
    normalized = timestamp
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    return int((parsed - epoch).total_seconds() * 1_000_000)


def _read_journal_with_docker(journal_path: Path) -> list[dict[str, Any]]:
    work_dir = journal_path.parent.resolve()
    mount = f"{work_dir}:/work"
    command = (
        "set -euo pipefail; "
        "dnf install -y -q systemd >/dev/null; "
        f"journalctl --file=/work/{journal_path.name} -o json --no-pager"
    )
    proc = subprocess.run(
        ["docker", "run", "--rm", "-v", mount, _JOURNAL_DOCKER_IMAGE, "bash", "-lc", command],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise JournalConversionError(
            f"Docker journalctl read failed: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return sorted(_journal_json_to_records(proc.stdout), key=lambda item: item["timestamp"])


def _read_journal_with_wsl(journal_path: Path) -> list[dict[str, Any]]:
    win_journal = str(journal_path)
    proc = subprocess.run(
        ["wsl", "-e", "bash", "-lc", f"journalctl --file='{win_journal}' -o json --no-pager"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise JournalConversionError(
            f"WSL journalctl read failed: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return sorted(_journal_json_to_records(proc.stdout), key=lambda item: item["timestamp"])


def _journal_json_to_records(stdout: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        payload = json.loads(stripped)
        realtime = payload.get("__REALTIME_TIMESTAMP")
        timestamp = ""
        if isinstance(realtime, str) and realtime.isdigit():
            seconds = int(realtime) / 1_000_000
            timestamp = _format_unix_micro_timestamp(seconds)
        records.append(
            {
                "priority": str(payload.get("PRIORITY", "")),
                "timestamp": timestamp,
                "hostname": str(payload.get("_HOSTNAME", "")),
                "appname": str(payload.get("SYSLOG_IDENTIFIER", "")),
                "message": str(payload.get("MESSAGE", "")),
            }
        )
    return records


def _format_unix_micro_timestamp(seconds: float) -> str:
    whole = int(seconds)
    micro = int(round((seconds - whole) * 1_000_000))
    base = datetime.fromtimestamp(whole, UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{micro:06d}Z"


def _normalize_compare_value(value: Any) -> str:
    text = str(value).strip()
    if not text:
        return ""
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return str(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
