"""Shared utilities for SOC-bench truth projectors."""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from socbench.capture.models import CanonicalEvent
from socbench.truth.errors import SocbenchTruthError

DEFAULT_STAGE_MINUTES = 30

ScaleLabel = Literal["isolated", "localized", "campaign_scale"]
TypeLabel = Literal["ransomware_like", "non_ransom_coordinated", "uncertain"]

# Auth-burst detection for campaign_scale (explicit assumptions — see fox manifest).
AUTH_BURST_MIN_EVENTS = 3
AUTH_BURST_WINDOW_MINUTES = 5

AUTH_EVENT_KINDS = frozenset(
    {
        "logon",
        "failed_logon",
        "explicit_credentials",
        "ssh_session",
        "rdp_session",
    }
)

RANSOMWARE_TECHNIQUE = "T1486"

_REMOTE_HOST_PATTERN = re.compile(
    r"(?:\\\\|\\/)([A-Za-z0-9][A-Za-z0-9_-]{0,62})(?:\\|/|$|\s)",
)

_ENCRYPT_UNC_PATTERN = re.compile(r"\\\\[^\s\\]+\\[^\s\\]+")
_OVERESCAPED_UNC_PATTERN = re.compile(r"(\\{2,})([A-Za-z0-9][A-Za-z0-9_-]*)(\\{2,})([A-Za-z0-9][A-Za-z0-9_-]*)")
_FILE_ARTIFACT_PATTERN = re.compile(r"([\w\-.]+\.(?:zip|7z|rar|tar|gz|dmp))", re.IGNORECASE)


@dataclass(frozen=True)
class PrecursorMarker:
    """One ransomware precursor category from interpretation guidance."""

    category: str
    attack_ids: frozenset[str] = frozenset()
    kinds: frozenset[str] = frozenset()
    windows_event_id: str | None = None


# Reusable across fox.py, goat.py, and tiger.py.
RANSOMWARE_PRECURSOR_MARKERS: tuple[PrecursorMarker, ...] = (
    PrecursorMarker(
        category="T1569.002",
        attack_ids=frozenset({"T1569.002"}),
    ),
    PrecursorMarker(
        category="T1021.002",
        attack_ids=frozenset({"T1021.002"}),
    ),
    PrecursorMarker(
        category="event_7045",
        kinds=frozenset({"service_installed"}),
        windows_event_id="7045",
    ),
)


def load_canonical_events(path: Path) -> list[CanonicalEvent]:
    """Load canonical NDJSON records in file order."""
    path = path.resolve()
    if not path.is_file():
        msg = f"Canonical events file not found: {path}"
        raise SocbenchTruthError(msg)
    events: list[CanonicalEvent] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
            events.append(CanonicalEvent.model_validate(payload))
        except (json.JSONDecodeError, ValueError) as exc:
            msg = f"Invalid canonical event at {path}:{line_no}"
            raise SocbenchTruthError(msg) from exc
    return events


def parse_ts(ts: str) -> datetime:
    """Parse ISO-8601 timestamps from canonical events."""
    normalized = ts.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def infer_window_start(events: list[CanonicalEvent]) -> datetime:
    """Infer timeline origin as the earliest event timestamp."""
    if not events:
        msg = "Cannot infer window start from empty canonical event list"
        raise SocbenchTruthError(msg)
    return min(parse_ts(event.ts) for event in events)


def stage_of(
    ts: str | datetime,
    window_start: datetime,
    *,
    stage_minutes: int = DEFAULT_STAGE_MINUTES,
) -> int:
    """Return zero-based stage index for a timestamp."""
    if stage_minutes <= 0:
        msg = f"stage_minutes must be positive, got {stage_minutes}"
        raise SocbenchTruthError(msg)
    event_time = parse_ts(ts) if isinstance(ts, str) else ts.astimezone(UTC)
    origin = window_start.astimezone(UTC)
    delta_minutes = (event_time - origin).total_seconds() / 60.0
    if delta_minutes < 0:
        return 0
    return int(delta_minutes // stage_minutes)


def stage_end_ts(window_start: datetime, stage: int, *, stage_minutes: int) -> str:
    """Return ISO timestamp for the inclusive end of a stage."""
    end = window_start + timedelta(minutes=(stage + 1) * stage_minutes)
    return end.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def events_through_stage(
    events: list[CanonicalEvent],
    stage: int,
    window_start: datetime,
    *,
    stage_minutes: int = DEFAULT_STAGE_MINUTES,
) -> list[CanonicalEvent]:
    """Return cumulative canonical events through the requested stage."""
    return [
        event
        for event in events
        if stage_of(event.ts, window_start, stage_minutes=stage_minutes) <= stage
    ]


def index_by_evidence_id(events: list[CanonicalEvent]) -> dict[str, CanonicalEvent]:
    """Build an evidence_id lookup table."""
    return {event.evidence_id: event for event in events}


def resolve_evidence_id(
    evidence_id: str, events_by_id: dict[str, CanonicalEvent]
) -> CanonicalEvent:
    """Resolve a canonical event by evidence_id or raise."""
    try:
        return events_by_id[evidence_id]
    except KeyError as exc:
        msg = f"Unknown evidence_id: {evidence_id}"
        raise SocbenchTruthError(msg) from exc


def precursor_categories_for_event(event: CanonicalEvent) -> set[str]:
    """Return precursor marker categories from observable kind/fields only (DP2-safe)."""
    categories: set[str] = set()
    fields = event.fields
    kind = event.kind
    command_line = str(fields.get("command_line", "")).lower()
    process_name = str(fields.get("process_name", "")).lower()
    service_name = str(fields.get("service_name", "")).lower()
    service_file = str(fields.get("service_file_name", "")).lower()

    if kind == "service_installed":
        categories.add("event_7045")
        if "psex" in service_name or "psex" in service_file:
            categories.add("T1569.002")

    if kind == "process" and ("psexec" in command_line or "psexec" in process_name):
        categories.add("T1569.002")

    if kind == "explicit_credentials":
        categories.add("T1021.002")

    logon_type = fields.get("logon_type")
    if kind == "logon" and str(logon_type) == "3":
        categories.add("T1021.002")

    return categories


def distinct_precursor_categories(events: list[CanonicalEvent]) -> set[str]:
    """Return distinct precursor categories across a cumulative event slice."""
    categories: set[str] = set()
    for event in events:
        categories.update(precursor_categories_for_event(event))
    return categories


def is_ransomware_event(event: CanonicalEvent) -> bool:
    """Return True when observable process fields indicate encryption impact."""
    if event.kind != "process":
        return False
    command_line = str(event.fields.get("command_line", "")).lower()
    process_name = str(event.fields.get("process_name", "")).lower()
    return "encrypt" in command_line or "darkside" in process_name


def is_vss_delete_event(event: CanonicalEvent) -> bool:
    """Return True when observable process fields indicate shadow-copy deletion."""
    if event.kind != "process":
        return False
    command_line = str(event.fields.get("command_line", "")).lower()
    process_name = str(event.fields.get("process_name", "")).lower()
    return "vssadmin" in process_name and "delete shadows" in command_line


def extract_encrypt_paths(event: CanonicalEvent) -> list[str]:
    """Parse UNC share paths from observable encryptor command lines."""
    if not is_ransomware_event(event):
        return []
    command_line = str(event.fields.get("command_line", ""))
    target_section = command_line.split("--encrypt", maxsplit=1)
    payload = target_section[1] if len(target_section) == 2 else command_line
    payload = _normalize_overescaped_unc(payload)
    paths = _ENCRYPT_UNC_PATTERN.findall(payload)
    if paths:
        return paths
    return [
        f"\\\\{host}\\{share}"
        for _, host, _, share in _OVERESCAPED_UNC_PATTERN.findall(payload)
    ]


def _normalize_overescaped_unc(command_line: str) -> str:
    """Collapse GT-style over-escaped UNC tokens to standard \\\\HOST\\SHARE form."""

    def _replacer(match: re.Match[str]) -> str:
        host = match.group(2)
        share = match.group(4)
        return f"\\\\{host}\\{share}"

    return _OVERESCAPED_UNC_PATTERN.sub(_replacer, command_line)


def parse_share_path(unc_path: str) -> tuple[str, str, str]:
    """Return (host, share, full_path) for a UNC path like \\\\FS-01\\Finance."""
    normalized = unc_path.replace("/", "\\")
    parts = [part for part in normalized.split("\\") if part]
    if len(parts) < 2:
        return "", "", unc_path
    host = parts[0].upper()
    share = parts[1]
    return host, share, unc_path


def estimate_share_total_bytes(host: str, share: str) -> int:
    """Deterministic share volume placeholder until hostmetrics source lands."""
    from socbench.capture.hashing import stable_seed

    rng = random.Random(stable_seed(f"goat_share:{host}:{share}"))
    return rng.randint(80_000_000, 420_000_000)


def extract_file_artifacts_from_event(event: CanonicalEvent) -> set[str]:
    """Return normalized file artifact names referenced by observable fields."""
    artifacts: set[str] = set()
    staged = event.fields.get("staged_archive")
    if isinstance(staged, str) and staged.strip():
        artifacts.add(normalize_file_artifact(staged))
    for field_name in ("command_line", "process_name"):
        raw = event.fields.get(field_name)
        if not isinstance(raw, str):
            continue
        for match in _FILE_ARTIFACT_PATTERN.findall(raw):
            artifacts.add(normalize_file_artifact(match))
    return artifacts


def normalize_file_artifact(value: str) -> str:
    """Normalize a path or filename to a lowercase basename for matching."""
    cleaned = value.replace("\\", "/").strip().strip("'\"")
    basename = cleaned.rsplit("/", maxsplit=1)[-1]
    return basename.lower()


def is_psexec_launcher_event(event: CanonicalEvent) -> bool:
    """Return True when observable fields indicate a PsExec remote launcher."""
    if event.kind != "process":
        return False
    command_line = str(event.fields.get("command_line", "")).lower()
    process_name = str(event.fields.get("process_name", "")).lower()
    return "psexec" in command_line or "psexec" in process_name


def psexec_target_hosts(event: CanonicalEvent) -> set[str]:
    """Extract remote target hostnames from a PsExec launcher command line."""
    if not is_psexec_launcher_event(event):
        return set()
    return {host.upper() for host in referenced_remote_hostnames(event)}


def is_psexec_helper_service(event: CanonicalEvent) -> bool:
    """Return True when observable fields indicate a PsExec helper service install."""
    if event.kind != "service_installed":
        return False
    service_name = str(event.fields.get("service_name", "")).upper()
    service_file = str(event.fields.get("service_file_name", "")).lower()
    return service_name == "PSEXESVC" or "psexesvc" in service_file


def is_initial_access_event(event: CanonicalEvent) -> bool:
    """Detect observable initial-access markers without grader phase labels."""
    fields = event.fields
    if event.kind == "connection":
        source_ip = fields.get("source_ip")
        dst_ip = fields.get("dst_ip")
        if isinstance(source_ip, str) and is_external_ip(source_ip):
            return True
        if isinstance(dst_ip, str) and is_external_ip(dst_ip) and _is_internal_ip(
            str(fields.get("source_ip", ""))
        ):
            return False
    if event.kind in {"ssh_session", "rdp_session"}:
        source_ip = fields.get("source_ip")
        return isinstance(source_ip, str) and is_external_ip(source_ip)
    return False


def is_external_ip(ip: str) -> bool:
    """Return True when an IP is not RFC1918-style internal space."""
    return not _is_internal_ip(ip)


def connection_bytes(event: CanonicalEvent) -> int:
    """Return best-effort outbound byte count for a connection event."""
    orig_bytes = event.fields.get("orig_bytes")
    if isinstance(orig_bytes, int):
        return orig_bytes
    if isinstance(orig_bytes, str) and orig_bytes.isdigit():
        return int(orig_bytes)
    return 0


def protocol_label(event: CanonicalEvent) -> str:
    """Map a connection event to a coarse protocol label."""
    service = str(event.fields.get("service", "")).lower()
    dst_port = event.fields.get("dst_port")
    if service in {"ssl", "tls", "https"} or dst_port == 443:
        return "https"
    if service == "ftp" or dst_port == 21:
        return "ftp"
    if service:
        return service
    if isinstance(dst_port, int):
        return str(dst_port)
    return "unknown"


def is_exfil_connection_event(event: CanonicalEvent) -> bool:
    """Detect outbound exfiltration connections from observable fields."""
    if event.kind != "connection":
        return False
    dst_ip = event.fields.get("dst_ip")
    if not isinstance(dst_ip, str) or not is_external_ip(dst_ip):
        return False
    return connection_bytes(event) > 0 or event.fields.get("dst_port") in {21, 443}


def is_staging_event(event: CanonicalEvent) -> bool:
    """Detect staging activity that precedes or supports exfiltration."""
    if event.kind == "connection":
        dst_ip = event.fields.get("dst_ip")
        dst_port = event.fields.get("dst_port")
        if isinstance(dst_ip, str) and _is_internal_ip(dst_ip):
            if dst_port in {21, 445, 139}:
                return True
    if event.kind == "process":
        command_line = str(event.fields.get("command_line", "")).lower()
        if event.fields.get("staged_archive"):
            return True
        if "compress-archive" in command_line or "uploadfile(" in command_line:
            return True
    return False


def _is_internal_ip(ip: str) -> bool:
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")


def infer_ip_to_host(events: list[CanonicalEvent]) -> dict[str, str]:
    """Infer internal IP→hostname mapping from canonical event fields only."""
    ip_to_host: dict[str, str] = {}

    for event in events:
        dst_ip = event.fields.get("dst_ip")
        if isinstance(dst_ip, str) and _is_internal_ip(dst_ip):
            if event.kind in {"connection", "ssh_session", "rdp_session"}:
                ip_to_host.setdefault(dst_ip, event.host)

        source_ip = event.fields.get("source_ip")
        if isinstance(source_ip, str) and _is_internal_ip(source_ip):
            if event.kind in {"connection", "ssh_session"} and event.host:
                ip_to_host.setdefault(source_ip, event.host)

    return ip_to_host


def referenced_remote_hostnames(event: CanonicalEvent) -> set[str]:
    """Extract hostnames referenced by remote-exec style command lines."""
    hostnames: set[str] = set()
    for field_name in ("command_line", "process_name"):
        raw = event.fields.get(field_name)
        if not isinstance(raw, str):
            continue
        for match in _REMOTE_HOST_PATTERN.findall(raw):
            hostnames.add(match.upper())
    target_server = event.fields.get("target_server")
    if isinstance(target_server, str) and target_server:
        hostnames.add(target_server.upper())
    return hostnames


def normalize_hostname(hostname: str) -> str:
    """Normalize hostnames for graph vertices."""
    return hostname.strip().upper()


def connected_components(
    hosts: set[str],
    edges: set[tuple[str, str]],
) -> list[set[str]]:
    """Return connected components for an undirected host graph."""
    adjacency: dict[str, set[str]] = {host: set() for host in hosts}
    for left, right in edges:
        if left in adjacency and right in adjacency:
            adjacency[left].add(right)
            adjacency[right].add(left)

    seen: set[str] = set()
    components: list[set[str]] = []
    for host in sorted(hosts):
        if host in seen:
            continue
        stack = [host]
        component: set[str] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            component.add(current)
            stack.extend(sorted(adjacency[current] - seen))
        components.append(component)
    return components


def auth_burst_detected(
    events: list[CanonicalEvent],
    *,
    min_events: int = AUTH_BURST_MIN_EVENTS,
    window_minutes: int = AUTH_BURST_WINDOW_MINUTES,
) -> bool:
    """Detect coordinated auth bursts across hosts inside a sliding time window."""
    auth_events = [event for event in events if event.kind in AUTH_EVENT_KINDS]
    if len(auth_events) < min_events:
        return False

    ordered = sorted(auth_events, key=lambda event: parse_ts(event.ts))
    window = timedelta(minutes=window_minutes)
    end_idx = 0
    for start_idx, start_event in enumerate(ordered):
        start_time = parse_ts(start_event.ts)
        while end_idx < len(ordered) and parse_ts(ordered[end_idx].ts) - start_time <= window:
            end_idx += 1
        window_slice = ordered[start_idx:end_idx]
        if len(window_slice) >= min_events and len({event.host for event in window_slice}) >= 2:
            return True
        if end_idx == start_idx:
            end_idx += 1
    return False


def build_host_interaction_graph(
    events: list[CanonicalEvent],
) -> tuple[set[str], set[tuple[str, str]], dict[str, Any]]:
    """Build affected-host graph using verifiable cross-host interactions."""
    affected_hosts = {normalize_hostname(event.host) for event in events}
    ip_to_host = {ip: normalize_hostname(host) for ip, host in infer_ip_to_host(events).items()}
    edges: set[tuple[str, str]] = set()
    edge_records: list[dict[str, Any]] = []

    uid_hosts: dict[str, set[str]] = {}
    logon_hosts: dict[str, set[str]] = {}

    for event in events:
        host = normalize_hostname(event.host)
        fields = event.fields

        source_ip = fields.get("source_ip")
        if isinstance(source_ip, str) and source_ip in ip_to_host:
            source_host = ip_to_host[source_ip]
            if source_host in affected_hosts and source_host != host:
                edge = tuple(sorted((source_host, host)))
                if edge not in edges:
                    edges.add(edge)
                    edge_records.append(
                        {
                            "left": edge[0],
                            "right": edge[1],
                            "rule": "source_ip_to_target_host",
                            "evidence_id": event.evidence_id,
                        }
                    )

        dst_ip = fields.get("dst_ip")
        if event.kind == "connection" and isinstance(dst_ip, str) and dst_ip in ip_to_host:
            dst_host = ip_to_host[dst_ip]
            if dst_host in affected_hosts and dst_host != host:
                edge = tuple(sorted((host, dst_host)))
                if edge not in edges:
                    edges.add(edge)
                    edge_records.append(
                        {
                            "left": edge[0],
                            "right": edge[1],
                            "rule": "connection_dst_ip",
                            "evidence_id": event.evidence_id,
                        }
                    )

        for remote_host in referenced_remote_hostnames(event):
            normalized_remote = normalize_hostname(remote_host)
            if normalized_remote in affected_hosts and normalized_remote != host:
                edge = tuple(sorted((host, normalized_remote)))
                if edge not in edges:
                    edges.add(edge)
                    edge_records.append(
                        {
                            "left": edge[0],
                            "right": edge[1],
                            "rule": "remote_exec_or_target_server",
                            "evidence_id": event.evidence_id,
                        }
                    )

        uid = fields.get("uid")
        if isinstance(uid, str) and uid and uid != "(filtered by sensor placement)":
            uid_hosts.setdefault(uid, set()).add(host)

        logon_id = fields.get("logon_id")
        if isinstance(logon_id, str) and logon_id:
            logon_hosts.setdefault(logon_id, set()).add(host)

    for uid, hosts in uid_hosts.items():
        if len(hosts) < 2:
            continue
        host_list = sorted(hosts)
        for left, right in _pairwise(host_list):
            edge = (left, right)
            if edge not in edges:
                edges.add(edge)
                edge_records.append(
                    {
                        "left": left,
                        "right": right,
                        "rule": "shared_connection_uid",
                        "uid": uid,
                    }
                )

    for logon_id, hosts in logon_hosts.items():
        if len(hosts) < 2:
            continue
        host_list = sorted(hosts)
        for left, right in _pairwise(host_list):
            edge = (left, right)
            if edge not in edges:
                edges.add(edge)
                edge_records.append(
                    {
                        "left": left,
                        "right": right,
                        "rule": "shared_logon_id",
                        "logon_id": logon_id,
                    }
                )

    graph_metadata = {
        "ip_to_host": ip_to_host,
        "edge_records": edge_records,
        "assumption": (
            "Host adjacency follows verifiable observable interactions "
            "(source_ip/logon, dst_ip connection, remote-exec hostname, shared uid/logon_id)."
        ),
    }
    return affected_hosts, edges, graph_metadata


def _pairwise(sorted_hosts: list[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for idx, left in enumerate(sorted_hosts):
        for right in sorted_hosts[idx + 1 :]:
            pairs.append((left, right))
    return pairs


def classify_scale_label(
    affected_hosts: set[str],
    edges: set[tuple[str, str]],
    *,
    auth_burst: bool,
) -> ScaleLabel | None:
    """Classify o1_scale from the affected-host interaction graph."""
    if not affected_hosts:
        return None

    host_count = len(affected_hosts)
    if host_count == 1:
        return "isolated"

    components = connected_components(affected_hosts, edges)
    largest_component = max(components, key=len)

    if auth_burst and host_count >= 2:
        return "campaign_scale"

    if host_count >= 3:
        return "campaign_scale"

    if host_count == 2:
        if len(largest_component) == 2 and edges:
            return "localized"
        return "campaign_scale"

    return "campaign_scale"


def classify_type_label(
    events: list[CanonicalEvent],
    *,
    scale_label: ScaleLabel | None,
) -> TypeLabel | None:
    """Classify o2_type from cumulative precursor marker categories."""
    if not events:
        return None

    categories = distinct_precursor_categories(events)
    if len(categories) >= 2:
        return "ransomware_like"
    if len(categories) == 1:
        if scale_label in {"localized", "campaign_scale"}:
            return "non_ransom_coordinated"
        return "uncertain"
    return "uncertain"
