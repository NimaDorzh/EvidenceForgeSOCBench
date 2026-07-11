#!/usr/bin/env python3
"""One-off audit script for canonical_events.ndjson integrity checks."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

REQUIRED = ["evidence_id", "ts", "phase", "attack", "host", "kind", "observed_by", "output_refs"]
ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
EVID_RE = re.compile(r"^EVID-\d{6}$")


def parse_ref(ref: str) -> tuple[str, str, int | None]:
    if "#L" in ref:
        path_part, _, line_s = ref.partition("#L")
        return path_part, "line", int(line_s)
    if "#rec" in ref:
        path_part, _, rec_s = ref.partition("#rec")
        return path_part, "rec", int(rec_s)
    return ref, "unknown", None


def line_consistent(fmt: str, line: str, fields: dict) -> bool:
    for key in ("uid", "command_line", "query"):
        value = fields.get(key)
        if isinstance(value, str) and value in line:
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
        pid = fields.get("pid")
        if isinstance(pid, int) and f'<Data Name="ProcessId">{pid}</Data>' in line:
            return True
    if fmt in {"proxy_access", "web_access", "cisco_asa", "snort_alert", "ecar"}:
        for key in ("command_line", "dst_ip", "uid", "query"):
            value = fields.get(key)
            if isinstance(value, str) and value in line:
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
    }
    if not ndjson.exists():
        report["missing_ndjson"] = str(ndjson)
        return report

    events = [json.loads(line) for line in ndjson.read_text(encoding="utf-8").splitlines() if line.strip()]
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
            if not any(key in event for key in ("observable", "unobservable", "observation_status")):
                report["unobservable_flag_missing"].append(evidence_id)
        if not output_refs:
            report["empty_output_refs"].append(evidence_id)

        fields = event.get("fields", {})
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
                if not line_consistent(fmt, lines[anchor - 1], fields):
                    report["ref_issues"].append(
                        f"{evidence_id}/{fmt}: line content not consistent with event fields"
                    )
            elif anchor_kind == "rec" and anchor is not None:
                event_count = text.count("<Event ")
                if anchor < 1 or anchor > event_count:
                    report["ref_issues"].append(
                        f"{evidence_id}/{fmt}: #rec{anchor} out of range in {path_part}"
                    )

    numbers = [int(value.split("-")[1]) for value in evidence_ids if EVID_RE.fullmatch(value)]
    if numbers != list(range(len(numbers))):
        report["schema_issues"].append(f"non-contiguous evidence_id sequence: {numbers}")
    if len(numbers) != len(set(numbers)):
        report["schema_issues"].append("duplicate evidence_id values")

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
    ]
    reports = [audit_bundle(name, path) for name, path in bundles]
    print(json.dumps(reports, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
