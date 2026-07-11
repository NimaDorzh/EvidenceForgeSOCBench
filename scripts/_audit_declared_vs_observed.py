"""Audit declared scenario fields vs canonical observed fields (colonial)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

from evidenceforge.models.scenario import Scenario
from socbench.capture.canonical_events import build_canonical_events

REPO_ROOT = Path(__file__).resolve().parents[1]
BUNDLE = REPO_ROOT / "scenarios" / "colonial-pipeline"
SCENARIO = BUNDLE / "scenario.yaml"

COMPARE_FIELDS = (
    "source_ip",
    "dst_ip",
    "dst_port",
    "service",
    "logon_type",
    "service_name",
    "service_file_name",
    "target_username",
    "target_server",
    "orig_bytes",
    "hostname",
)

TIGER_EXTRA_FIELDS = (
    "pid",
    "ppid",
    "logon_id",
    "process_name",
    "command_line",
    "service_name",
    "service_file_name",
    "target_process",
    "uid",
    "source_ip",
    "dst_ip",
    "dst_port",
)

CRITICAL_STEPS = frozenset(
    {
        "evt-003",
        "evt-004",
        "evt-004b",
        "evt-005",
        "evt-005b",
        "evt-006a",
        "evt-006b",
    }
)


def _declared_by_record(scenario: Scenario) -> dict[str, dict[str, object]]:
    mapping: dict[str, dict[str, object]] = {}
    for step in scenario.storyline or []:
        for idx, spec in enumerate(step.events):
            record_id = f"{step.id}#{idx}"
            declared: dict[str, object] = {}
            for field in COMPARE_FIELDS:
                val = getattr(spec, field, None)
                if val is not None:
                    declared[field] = val
            mapping[record_id] = declared
    return mapping


def main() -> int:
    scenario = Scenario.model_validate(yaml.safe_load(SCENARIO.read_text(encoding="utf-8")))
    events = build_canonical_events(BUNDLE, scenario, seed=42)
    declared_by_record = _declared_by_record(scenario)

    rows: list[dict[str, object]] = []
    for event in events:
        record_id = event.record_id or ""
        declared = declared_by_record.get(record_id, {})
        for field in COMPARE_FIELDS:
            if field not in declared:
                continue
            dec = declared[field]
            obs = event.fields.get(field)
            if obs is None and field == "service":
                obs = event.fields.get("protocol")
            if obs is None:
                match = "N/A"
            elif str(dec) == str(obs):
                match = "Y"
            else:
                match = "N"
            rows.append(
                {
                    "step": record_id.rsplit("#", 1)[0],
                    "record": record_id,
                    "kind": event.kind,
                    "field": field,
                    "declared": dec,
                    "observed": obs,
                    "match": match,
                    "evidence_id": event.evidence_id,
                }
            )

    print(f"Total comparisons: {len(rows)}")
    header = (
        f"{'step':<10} {'record':<12} {'kind':<22} {'field':<18} "
        f"{'declared':<24} {'observed':<24} match"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            f"{row['step']!s:<10} {row['record']!s:<12} {row['kind']!s:<22} "
            f"{row['field']!s:<18} {str(row['declared'])!s:<24} "
            f"{str(row['observed'])!s:<24} {row['match']!s}"
        )

    print("\n=== MISMATCHES (match=N) ===")
    mismatches = [row for row in rows if row["match"] == "N"]
    for row in mismatches:
        print(
            f"{row['record']} {row['field']}: declared={row['declared']} "
            f"observed={row['observed']} ({row['evidence_id']})"
        )

    print("\n=== CRITICAL TIGER CORRELATION FIELDS ===")
    for event in events:
        if event.storyline_id not in CRITICAL_STEPS:
            continue
        extra = {
            key: event.fields[key]
            for key in TIGER_EXTRA_FIELDS
            if event.fields.get(key) is not None
        }
        print(f"{event.record_id} ({event.kind}): {json.dumps(extra, default=str)}")

    return 0 if not mismatches else 1


if __name__ == "__main__":
    sys.exit(main())
