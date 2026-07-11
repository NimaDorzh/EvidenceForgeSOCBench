#!/usr/bin/env python3
"""Audit GT/scenario dst_port vs Zeek for connection storyline events."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml


def zeek_row_for_uid(data_root: Path, uid: str) -> dict[str, Any] | None:
    needle = f'"uid":"{uid}"'
    for path in sorted(data_root.rglob("conn.json")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if needle not in line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                return {
                    "path": str(path.relative_to(data_root.parent)),
                    "resp_h": row.get("id.resp_h"),
                    "resp_p": row.get("id.resp_p"),
                    "service": row.get("service"),
                }
    return None


def scenario_connections(scenario_path: Path) -> dict[str, dict[str, Any]]:
    doc = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {}
    for step in doc.get("storyline", []):
        storyline_id = step.get("id", "")
        for idx, event in enumerate(step.get("events", [])):
            if event.get("type") != "connection":
                continue
            record_id = f"{storyline_id}#{idx}"
            out[record_id] = {
                "storyline_id": storyline_id,
                "dst_ip": event.get("dst_ip"),
                "dst_port": event.get("dst_port"),
                "service": event.get("service"),
            }
    return out


def audit_bundle(bundle: Path, scenario_path: Path | None) -> list[dict[str, Any]]:
    gt_path = bundle / "GROUND_TRUTH.json"
    data_root = bundle / "data"
    if not gt_path.exists():
        return []
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    scenario_map = scenario_connections(scenario_path) if scenario_path and scenario_path.exists() else {}

    rows: list[dict[str, Any]] = []
    for item in gt["events"]:
        if item.get("ground_truth_section") != "storyline" or not item.get("emitted"):
            continue
        if item.get("kind") != "connection":
            continue
        record_id = item.get("record_id", "")
        attrs = item.get("attributes") or {}
        uid = attrs.get("uid")
        gt_port = attrs.get("dst_port")
        gt_ip = attrs.get("dst_ip")
        scen = scenario_map.get(record_id, {})
        zeek = zeek_row_for_uid(data_root, uid) if isinstance(uid, str) and uid else None
        zeek_port = zeek.get("resp_p") if zeek else None
        zeek_service = zeek.get("service") if zeek else None
        port_match = zeek_port is not None and gt_port is not None and int(zeek_port) == int(gt_port)
        rows.append(
            {
                "bundle": bundle.name,
                "record_id": record_id,
                "storyline_id": item.get("storyline_id"),
                "system": item.get("system"),
                "gt_dst_ip": gt_ip,
                "gt_dst_port": gt_port,
                "scenario_service": scen.get("service"),
                "scenario_dst_port": scen.get("dst_port"),
                "uid": uid,
                "zeek_path": zeek.get("path") if zeek else None,
                "zeek_resp_port": zeek_port,
                "zeek_service": zeek_service,
                "port_match": port_match,
            }
        )
    return rows


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    bundles = [
        (repo / "scenarios" / "colonial-pipeline", repo / "scenarios" / "colonial-pipeline" / "scenario.yaml"),
        (repo / "output" / "retail-test", repo / "output" / "retail-test" / "scenario.yaml"),
        (repo / "output" / "branch-office-test", repo / "output" / "branch-office-test" / "scenario.yaml"),
    ]
    all_rows: list[dict[str, Any]] = []
    for bundle, scenario in bundles:
        if bundle.is_dir():
            all_rows.extend(audit_bundle(bundle, scenario))

    ssl_claimed = [
        r
        for r in all_rows
        if r.get("scenario_service") in {"ssl", "https", "tls"}
        or r.get("gt_dst_port") == 443
    ]
    ssl_confirmed_443 = [r for r in ssl_claimed if r.get("zeek_resp_port") == 443]
    mismatches = [r for r in all_rows if r.get("uid") and not r.get("port_match")]

    print(json.dumps({"connections": all_rows, "ssl_claimed": ssl_claimed, "ssl_confirmed_443": ssl_confirmed_443, "mismatches": mismatches}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
