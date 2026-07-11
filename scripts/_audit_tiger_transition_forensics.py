"""Deep Tiger transition forensics for colonial critical edges."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from evidenceforge.models.scenario import Scenario
from socbench.capture.canonical_events import build_canonical_events

BUNDLE = Path(__file__).resolve().parents[1] / "scenarios" / "colonial-pipeline"
DATA = BUNDLE / "data"
_XML_SPLIT = re.compile(r"(?=<Event[\s>])")
_XML_DATA = re.compile(r'<Data Name="([^"]+)">([^<]*)</Data>')
_XML_EID = re.compile(r"<EventID>(\d+)</EventID>")


def _sysmon_event(path: Path, rec: int) -> dict[str, str]:
    chunks = _XML_SPLIT.split(path.read_text(encoding="utf-8"))
    chunk = chunks[rec]
    data = dict(_XML_DATA.findall(chunk))
    eid = _XML_EID.search(chunk)
    return {"event_id": eid.group(1) if eid else "", **data}


def _grep_ppid_for_pid(host_dir: Path, pid: int) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    pid_s = str(pid)
    for path in sorted(host_dir.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if pid_s not in text:
            continue
        if path.name == "windows_event_sysmon.xml":
            chunks = _XML_SPLIT.split(text)
            for idx, chunk in enumerate(chunks, start=0):
                if f"<Data Name=\"ProcessId\">{pid_s}</Data>" not in chunk:
                    continue
                data = dict(_XML_DATA.findall(chunk))
                if data.get("ProcessId") == pid_s and _XML_EID.search(chunk):
                    eid = _XML_EID.search(chunk).group(1)
                    hits.append(
                        {
                            "source": str(path.relative_to(BUNDLE)),
                            "anchor": f"rec{idx}",
                            "event_id": eid,
                            "pid": data.get("ProcessId"),
                            "ppid": data.get("ParentProcessId"),
                            "parent_image": data.get("ParentImage"),
                            "image": data.get("Image"),
                            "command_line": data.get("CommandLine", "")[:120],
                        }
                    )
        elif path.name == "ecar.json":
            for line_no, line in enumerate(text.splitlines(), start=1):
                if pid_s not in line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(row.get("pid")) != pid_s:
                    continue
                props = row.get("properties") or {}
                hits.append(
                    {
                        "source": str(path.relative_to(BUNDLE)),
                        "anchor": f"L{line_no}",
                        "object": row.get("object"),
                        "action": row.get("action"),
                        "pid": row.get("pid"),
                        "ppid": row.get("ppid"),
                        "parent_image": props.get("parent_image_path"),
                        "image": props.get("image_path"),
                        "command_line": str(props.get("command_line", ""))[:120],
                        "logon_id": props.get("logon_id"),
                    }
                )
        elif path.name == "windows_event_security.xml":
            if f"ProcessId\">{pid_s}</" in text or f"ProcessId\">{pid_s}<" in text:
                hits.append({"source": str(path.relative_to(BUNDLE)), "note": "pid mentioned"})
    return hits


def main() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load((BUNDLE / "scenario.yaml").read_text(encoding="utf-8"))
    )
    events = build_canonical_events(BUNDLE, scenario, seed=42)
    by_rid = {event.record_id: event for event in events if event.record_id}

    print("=== evt-003 -> evt-004 (procdump 5496 vs PsExec 5508) ===")
    ops_dir = DATA / "WKS-OPS-01.colonial-energy.local"
    sysmon = ops_dir / "windows_event_sysmon.xml"
    for rec in (58, 104):
        data = _sysmon_event(sysmon, rec)
        print(
            f"Sysmon {rec}: EventID={data.get('event_id')} pid={data.get('ProcessId')} "
            f"ppid={data.get('ParentProcessId')} parent={data.get('ParentImage')} "
            f"image={data.get('Image')}"
        )
    print("grep ppid references to 5496 under WKS-OPS-01:")
    for hit in _grep_ppid_for_pid(ops_dir, 5496):
        print(" ", hit)
    print("full lineage for pid=5508:")
    for hit in _grep_ppid_for_pid(ops_dir, 5508):
        print(" ", hit)
    print(
        "ppid=5496 anywhere for PsExec?",
        any(str(h.get("ppid")) == "5496" for h in _grep_ppid_for_pid(ops_dir, 5508)),
    )

    print("\n=== evt-004 -> evt-004b (PsExec launcher vs PSEXESVC service) ===")
    p4 = by_rid["evt-004#0"]
    s4b = by_rid["evt-004b#0"]
    print("launcher cmd:", p4.fields.get("command_line"))
    print("service:", s4b.fields.get("service_name"), s4b.fields.get("service_file_name"))
    fs_sysmon = _sysmon_event(DATA / "FS-01.colonial-energy.local/windows_event_sysmon.xml", 327)
    print("FS-01 service-related security/sysmon sample unavailable at rec327; use GT refs")

    print("\n=== evt-005 -> evt-005b (SMB logon sessions) ===")
    l5 = by_rid["evt-005#1"]
    l5b = by_rid["evt-005b#0"]
    print("FS-01 logon:", l5.fields)
    print("FS-02 logon:", l5b.fields)
    print("same source_ip:", l5.fields.get("source_ip") == l5b.fields.get("source_ip"))
    print("same logon_id:", l5.fields.get("logon_id") == l5b.fields.get("logon_id"))

    print("\n=== evt-006a -> evt-006b (staging chain) ===")
    for rid in ("evt-006a#0", "evt-006a#1", "evt-006b#1"):
        ev = by_rid[rid]
        print(rid, ev.fields.get("pid"), ev.fields.get("command_line", "")[:100])
    fs_dir = DATA / "FS-01.colonial-energy.local"
    for pid in (5200, 5204, 5296):
        print(f"pid {pid} hits:")
        for hit in _grep_ppid_for_pid(fs_dir, pid):
            if hit.get("object") == "PROCESS" and hit.get("action") == "CREATE":
                print(" ", hit)


if __name__ == "__main__":
    main()
