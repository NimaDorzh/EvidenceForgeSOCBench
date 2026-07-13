"""Tests for observable field backfill from resolved output refs."""

from __future__ import annotations

import yaml

from evidenceforge.models.scenario import Scenario
from socbench.capture.canonical_events import build_canonical_events
from socbench.capture.output_refs import backfill_fields_from_output_refs
from tests.socbench.colonial_fixtures import (
    COLONIAL_FULL_BUNDLE,
    COLONIAL_SCENARIO,
    REQUIRES_COLONIAL_FULL_DATA,
)


@REQUIRES_COLONIAL_FULL_DATA
def test_backfill_rdp_source_ip_from_resolved_telemetry() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_FULL_BUNDLE, scenario, seed=42)
    rdp = next(event for event in events if event.evidence_id == "EVID-cdf56f97")
    assert rdp.fields["source_ip"] == "10.60.20.13"
    assert "source_ip" in backfill_fields_from_output_refs(
        kind=rdp.kind,
        fields={"dst_ip": "10.60.20.21", "dst_port": 3389, "uid": rdp.fields["uid"]},
        output_refs=rdp.output_refs,
        bundle_root=COLONIAL_FULL_BUNDLE,
    )


@REQUIRES_COLONIAL_FULL_DATA
def test_backfill_exfil_orig_bytes_from_zeek() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_FULL_BUNDLE, scenario, seed=42)
    exfil = next(event for event in events if event.evidence_id == "EVID-c0b7909b")
    assert exfil.fields.get("orig_bytes", 0) > 0


@REQUIRES_COLONIAL_FULL_DATA
def test_backfill_process_ppid_from_sysmon_and_ecar() -> None:
    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_FULL_BUNDLE, scenario, seed=42)
    procdump = next(event for event in events if event.record_id == "evt-003#0")
    psexec = next(event for event in events if event.record_id == "evt-004#0")
    xcopy = next(event for event in events if event.record_id == "evt-006a#1")

    assert procdump.fields.get("ppid") == 5464
    assert psexec.fields.get("ppid") == 5464
    assert xcopy.fields.get("ppid") == 3448
    assert procdump.fields.get("pid") == 5496
    assert psexec.fields.get("pid") == 5508
