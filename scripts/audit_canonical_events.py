#!/usr/bin/env python3
"""One-off audit script for canonical_events.ndjson integrity checks."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

REQUIRED = [
    "evidence_id",
    "ts",
    "phase",
    "attack",
    "host",
    "kind",
    "observed_by",
    "output_refs",
    "observation_status",
]
ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
EVID_RE = re.compile(r"^EVID-[0-9a-f]{8}$")

# Partial events documented as EXPECTED-A or data mismatch (not resolver debt).
KNOWN_PARTIAL_NOTES: dict[str, str] = {
    "EVID-79379b3d": (
        "EXPECTED-A: eCAR dropped by OBSERVATION_MANIFEST (DP4); Security/Sysmon present"
    ),
    "EVID-57bc5431": (
        "EXPECTED-A: boot-time lsass PID lacks eCAR PROCESS lifecycle; Sysmon Event 8 only"
    ),
    "EVID-5cbc8381": (
        "EF local bug: scenario/GT claim dst_port=443/ssl but Zeek/ASA/eCAR emit :80/http "
        "(uid C5YtR44NxGf2T3IjXN); resolver cannot fabricate :443 eCAR ref"
    ),
    "EVID-6bdaf0d3": "EXPECTED-A: zeek_conn filtered/dropped by manifest (DP4)",
    "EVID-547345ca": (
        "ASA perimeter log for VPN OpenVPN :1194 not present; zeek_conn resolves"
    ),
}


def parse_ref(ref: str) -> tuple[str, str, int | None]:
    if "#L" in ref:
        path_part, _, line_s = ref.partition("#L")
        return path_part, "line", int(line_s)
    if "#rec" in ref:
        path_part, _, rec_s = ref.partition("#rec")
        return path_part, "rec", int(rec_s)
    return ref, "unknown", None


def _normalize_ip(value: str) -> str:
    raw = value.strip().lower()
    if raw.startswith("::ffff:"):
        raw = raw.removeprefix("::ffff:")
    return raw


def _zeek_resp_port_for_uid(bundle: Path, uid: str, dst_ip: str | None = None) -> int | None:
    data_root = bundle / "data"
    if not data_root.is_dir():
        return None
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


def line_consistent(fmt: str, line: str, fields: dict, *, bundle: Path | None = None) -> bool:
    for key in ("uid", "command_line", "query"):
        value = fields.get(key)
        if isinstance(value, str) and len(value) >= 4 and value in line:
            return True
    pid = fields.get("pid")
    if isinstance(pid, int) and (
        f'"pid":{pid}' in line or f'<Data Name="ProcessId">{pid}</Data>' in line
    ):
        return True

    logon_id = fields.get("logon_id")
    if isinstance(logon_id, str) and logon_id and logon_id.lower() in line.lower():
        return True
    source_ip = fields.get("source_ip")
    if isinstance(source_ip, str) and source_ip:
        if source_ip in line or _normalize_ip(source_ip) in _normalize_ip(line):
            return True
    service_name = fields.get("service_name")
    if isinstance(service_name, str) and service_name and service_name in line:
        return True
    target_username = fields.get("target_username")
    if isinstance(target_username, str) and target_username:
        bare = target_username.split("\\")[-1]
        if target_username in line or bare in line:
            return True
    target_process = fields.get("target_process")
    if isinstance(target_process, str) and target_process:
        if target_process in line or target_process.split("\\")[-1].lower() in line.lower():
            return True

    if fmt == "zeek_conn":
        dst_ip = fields.get("dst_ip")
        dst_port = fields.get("dst_port")
        if dst_ip is not None and dst_port is not None:
            needle = f'"id.resp_h":"{dst_ip}","id.resp_p":{dst_port}'
            if needle in line:
                return True
        uid = fields.get("uid")
        if isinstance(uid, str) and uid in line:
            return True
    if fmt in {"windows_event_sysmon", "windows_event_security"}:
        command_line = fields.get("command_line")
        if isinstance(command_line, str) and command_line in line:
            return True
        if isinstance(pid, int) and f'<Data Name="ProcessId">{pid}</Data>' in line:
            return True
    if fmt in {"proxy_access", "web_access", "cisco_asa", "snort_alert", "syslog", "ecar"}:
        dst_ip = fields.get("dst_ip")
        dst_port = fields.get("dst_port")
        if isinstance(dst_ip, str) and dst_port is not None:
            ports = [int(dst_port)]
            uid = fields.get("uid")
            if isinstance(uid, str) and uid and bundle is not None:
                zeek_port = _zeek_resp_port_for_uid(bundle, uid, dst_ip)
                if zeek_port is not None and zeek_port not in ports:
                    ports.append(zeek_port)
            port_tokens = tuple(
                token
                for port in ports
                for token in (f"/{port}", f"DPT={port}", f":{port}", f'"{port}"')
            )
            if dst_ip in line and any(token in line for token in port_tokens):
                return True
        for key in ("command_line", "uid", "query"):
            value = fields.get(key)
            if isinstance(value, str) and len(value) >= 4 and value in line:
                return True
        if isinstance(pid, int) and f'"pid":{pid}' in line:
            return True
        if fmt == "syslog" and "sshd" in line and ("Accepted" in line or "Opened" in line):
            user = fields.get("user") or fields.get("actor")
            if isinstance(user, str) and user and user in line:
                return True
    return False


def audit_bundle(name: str, bundle: Path) -> dict:
    ndjson = bundle / "grader" / "canonical_events.ndjson"
    gt_path = bundle / "GROUND_TRUTH.json"
    report: dict = {
        "bundle": name,
        "events": 0,
        "schema_issues": [],
        "ref_issues": [],
        "obs_mismatch": [],
        "empty_observed_by": [],
        "empty_output_refs": [],
        "unobservable_flag_missing": [],
        "known_partial_notes": [],
    }
    if not ndjson.exists():
        report["missing_ndjson"] = str(ndjson)
        return report

    events = [
        json.loads(line) for line in ndjson.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    report["events"] = len(events)
    evidence_ids: list[str] = []

    for index, event in enumerate(events, start=1):
        for field in REQUIRED:
            if field not in event:
                report["schema_issues"].append(f"line {index}: missing {field}")

        evidence_id = event.get("evidence_id", "")
        evidence_ids.append(evidence_id)
        if not EVID_RE.fullmatch(evidence_id):
            report["schema_issues"].append(f"line {index}: invalid evidence_id {evidence_id!r}")

        timestamp = event.get("ts", "")
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            report["schema_issues"].append(f"line {index}: invalid ts {timestamp!r}: {exc}")

        phase = event.get("phase")
        if phase is None or phase == "":
            report["schema_issues"].append(f"line {index}: empty phase")

        for attack_id in event.get("attack", []):
            if not ATTACK_RE.match(attack_id):
                report["schema_issues"].append(f"line {index}: invalid attack id {attack_id!r}")

        observed_by = event.get("observed_by") or []
        output_refs = event.get("output_refs") or {}
        if set(observed_by) != set(output_refs):
            report["obs_mismatch"].append(
                {
                    "evidence_id": evidence_id,
                    "observed_by": observed_by,
                    "output_refs_keys": sorted(output_refs),
                }
            )
        if not observed_by:
            report["empty_observed_by"].append(evidence_id)
            if event.get("observation_status") != "unobserved":
                report["unobservable_flag_missing"].append(evidence_id)
        if not output_refs:
            report["empty_output_refs"].append(evidence_id)
        status = event.get("observation_status")
        if status not in {"observed", "partial", "unobserved"}:
            report["schema_issues"].append(f"line {index}: bad observation_status {status!r}")
        if set(observed_by) != set(output_refs):
            # already recorded in obs_mismatch above
            pass
        elif status == "observed" and event.get("unresolved_sources"):
            report["schema_issues"].append(
                f"line {index}: observed status with unresolved_sources={event.get('unresolved_sources')}"
            )
        elif status == "unobserved" and observed_by:
            report["schema_issues"].append(f"line {index}: unobserved with non-empty observed_by")
        elif status == "partial" and not event.get("unresolved_sources"):
            report["schema_issues"].append(f"line {index}: partial without unresolved_sources")
        elif status == "partial":
            note = KNOWN_PARTIAL_NOTES.get(evidence_id)
            if note:
                report["known_partial_notes"].append(
                    {"evidence_id": evidence_id, "note": note, "unresolved_sources": event.get("unresolved_sources")}
                )

        fields = dict(event.get("fields", {}))
        actor = event.get("actor")
        if isinstance(actor, str) and actor:
            fields.setdefault("actor", actor)
        for fmt, ref in output_refs.items():
            path_part, anchor_kind, anchor = parse_ref(ref)
            file_path = bundle / path_part
            if not file_path.exists():
                report["ref_issues"].append(f"{evidence_id}/{fmt}: missing file {path_part}")
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            if anchor_kind == "line" and anchor is not None:
                lines = text.splitlines()
                if anchor < 1 or anchor > len(lines):
                    report["ref_issues"].append(
                        f"{evidence_id}/{fmt}: #L{anchor} out of range in {path_part}"
                    )
                    continue
                if not line_consistent(fmt, lines[anchor - 1], fields, bundle=bundle):
                    report["ref_issues"].append(
                        f"{evidence_id}/{fmt}: line content not consistent with event fields"
                    )
            elif anchor_kind == "rec" and anchor is not None:
                event_count = text.count("<Event ")
                if anchor < 1 or anchor > event_count:
                    report["ref_issues"].append(
                        f"{evidence_id}/{fmt}: #rec{anchor} out of range in {path_part}"
                    )

    numbers = [value for value in evidence_ids if EVID_RE.fullmatch(value)]
    if len(numbers) != len(set(numbers)):
        report["schema_issues"].append("duplicate evidence_id values")
    if len(numbers) != len(evidence_ids):
        report["schema_issues"].append("one or more evidence_id values failed format check")

    timestamps = [event.get("ts") for event in events]
    if timestamps != sorted(timestamps):
        report["schema_issues"].append("events not sorted by ts ascending")

    if gt_path.exists():
        ground_truth = json.loads(gt_path.read_text(encoding="utf-8"))
        gt_attack = [
            item
            for item in ground_truth.get("events", [])
            if item.get("ground_truth_section") == "storyline" and item.get("emitted")
        ]
        report["ground_truth_attack_count"] = len(gt_attack)
        report["canonical_count"] = len(events)
        gt_record_ids = {item["record_id"] for item in gt_attack}
        canonical_record_ids = {event.get("record_id") for event in events}
        report["ground_truth_only"] = sorted(gt_record_ids - canonical_record_ids)
        report["canonical_only"] = sorted(canonical_record_ids - gt_record_ids)

    return report


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    bundles = [
        ("retail-test", repo / "output" / "retail-test"),
        ("branch-office-test", repo / "output" / "branch-office-test"),
        ("colonial-pipeline", repo / "scenarios" / "colonial-pipeline"),
    ]
    reports = [audit_bundle(name, path) for name, path in bundles]
    print(json.dumps(reports, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
