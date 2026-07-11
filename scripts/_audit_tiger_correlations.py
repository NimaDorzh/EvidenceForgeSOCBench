"""Tiger verifiable-edge correlation checks for colonial critical steps."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from evidenceforge.models.scenario import Scenario
from socbench.capture.canonical_events import build_canonical_events
from socbench.capture.output_refs import backfill_fields_from_output_refs

_XML_DATA_FIELD = re.compile(r'<Data Name="([^"]+)">([^<]*)</Data>')
_XML_EVENT_ID = re.compile(r"<EventID>(\d+)</EventID>")
_XML_EVENT_SPLIT = re.compile(r"(?=<Event[\s>])")

BUNDLE = Path(__file__).resolve().parents[1] / "scenarios" / "colonial-pipeline"
SCENARIO = BUNDLE / "scenario.yaml"

CRITICAL_RECORDS = (
    "evt-003#0",
    "evt-003#1",
    "evt-004#0",
    "evt-004b#0",
    "evt-005#0",
    "evt-005#1",
    "evt-005b#0",
    "evt-006a#0",
    "evt-006a#1",
    "evt-006b#0",
    "evt-006b#1",
)


def _sysmon_process_fields(bundle: Path, ref: str) -> dict[str, object]:
    path_part, _, anchor = ref.partition("#")
    if not anchor.startswith("rec"):
        return {}
    try:
        record_no = int(anchor.removeprefix("rec"))
    except ValueError:
        return {}
    path = bundle / path_part
    if not path.is_file():
        return {}
    chunks = _XML_EVENT_SPLIT.split(path.read_text(encoding="utf-8"))
    if record_no < 1 or record_no > len(chunks):
        return {}
    chunk = chunks[record_no - 1]
    event_id = _XML_EVENT_ID.search(chunk)
    if not event_id or event_id.group(1) != "1":
        return {}
    data = dict(_XML_DATA_FIELD.findall(chunk))
    result: dict[str, object] = {}
    if data.get("ProcessId"):
        result["pid"] = int(data["ProcessId"])
    if data.get("ParentProcessId"):
        result["ppid"] = int(data["ParentProcessId"])
    if data.get("Image"):
        result["process_name"] = data["Image"]
    return result


def main() -> None:
    scenario = Scenario.model_validate(yaml.safe_load(SCENARIO.read_text(encoding="utf-8")))
    events = build_canonical_events(BUNDLE, scenario, seed=42)
    by_rid = {event.record_id: event for event in events if event.record_id}

    for record_id in CRITICAL_RECORDS:
        event = by_rid[record_id]
        print(f"--- {record_id} {event.evidence_id} {event.kind}")
        print(f"  fields: {json.dumps(event.fields, default=str)}")
        print(f"  refs: {event.output_refs}")
        print(f"  status: {event.observation_status} unresolved={event.unresolved_sources}")

    print("\n=== TIGER EDGE CHECKS ===")
    p3 = by_rid["evt-003#0"].fields
    p4 = by_rid["evt-004#0"].fields
    print(f"003 procdump pid={p3.get('pid')} ppid={p3.get('ppid')}")
    print(f"004 PsExec pid={p4.get('pid')} ppid={p4.get('ppid')}")
    print(f"004 ppid == 003 pid? {p4.get('ppid') == p3.get('pid')}")

    s4b = by_rid["evt-004b#0"].fields
    print(f"004 process={p4.get('process_name')}")
    print(f"004b service_file={s4b.get('service_file_name')}")

    l5 = by_rid["evt-005#1"].fields
    l5b = by_rid["evt-005b#0"].fields
    print(f"005 logon_id={l5.get('logon_id')} source={l5.get('source_ip')}")
    print(f"005b logon_id={l5b.get('logon_id')} source={l5b.get('source_ip')}")
    print(f"Same logon_id FS-01/FS-02? {l5.get('logon_id') == l5b.get('logon_id')}")

    a0 = by_rid["evt-006a#0"].fields
    a1 = by_rid["evt-006a#1"].fields
    b1 = by_rid["evt-006b#1"].fields
    print(f"006a archive pid={a0.get('pid')}")
    print(f"006a xcopy pid={a1.get('pid')} ppid={a1.get('ppid')}")
    print(f"006b upload pid={b1.get('pid')} ppid={b1.get('ppid')}")
    print(f"006b upload ppid == 006a archive pid? {b1.get('ppid') == a0.get('pid')}")
    print(f"006b upload same pid as 006a archive? {b1.get('pid') == a0.get('pid')}")

    print("\n=== TELEMETRY-ONLY (refs backfill, empty GT baseline) ===")
    for record_id in CRITICAL_RECORDS:
        event = by_rid[record_id]
        telemetry = backfill_fields_from_output_refs(
            kind=event.kind,
            fields={},
            output_refs=event.output_refs,
            bundle_root=BUNDLE,
        )
        sysmon_ref = event.output_refs.get("windows_event_sysmon")
        if sysmon_ref:
            telemetry.update(_sysmon_process_fields(BUNDLE, sysmon_ref))
        print(f"{record_id}: {json.dumps(telemetry, default=str)}")

    print("\n=== evt-007#1 ZEEK TELEMETRY vs GT CANONICAL ===")
    ev7 = by_rid["evt-007#1"]
    zeek_only = backfill_fields_from_output_refs(
        kind=ev7.kind,
        fields={},
        output_refs={"zeek_conn": ev7.output_refs["zeek_conn"]},
        bundle_root=BUNDLE,
    )
    print(f"GT/canonical: dst_port={ev7.fields.get('dst_port')} service={ev7.fields.get('service')}")
    print(f"Zeek-only: {zeek_only}")


if __name__ == "__main__":
    main()
