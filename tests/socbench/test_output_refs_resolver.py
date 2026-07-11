"""Parametric resolver tests for socbench output_refs kind-specific matching."""



from __future__ import annotations



from pathlib import Path



import pytest



from socbench.capture.canonical_events import finalize_observation

from socbench.capture.models import CanonicalEvent

from socbench.capture.output_refs import resolve_output_refs



REPO_ROOT = Path(__file__).resolve().parents[2]

COLONIAL_BUNDLE = REPO_ROOT / "scenarios" / "colonial-pipeline"

COLONIAL_SCENARIO = COLONIAL_BUNDLE / "scenario.yaml"





def _event(kind: str, host: str, fields: dict, *, record_id: str = "evt-test#0") -> CanonicalEvent:

    return CanonicalEvent(

        evidence_id="EVID-test0000",

        ts="2024-06-03T08:00:00Z",

        host=host,

        actor="t.morgan",

        kind=kind,

        fields=fields,

        record_id=record_id,

    )





def _assert_observed(

    event: CanonicalEvent,

    data_root: Path,

    candidates: list[str],

) -> dict[str, str]:

    refs = resolve_output_refs(event, data_root, candidates)

    observed, unresolved, status = finalize_observation(candidates, refs)

    assert status == "observed", (refs, observed, unresolved)

    assert set(observed) == set(refs)

    assert not unresolved

    return refs





@pytest.mark.parametrize(

    ("host", "fields", "candidates"),

    [

        (

            "WKS-OPS-01",

            {"logon_id": "0xd5845f8", "source_ip": "10.60.10.10"},

            ["windows_event_security", "ecar"],

        ),

        (

            "FS-01",

            {"logon_id": "0xd19a595", "source_ip": "10.60.20.21"},

            ["windows_event_security"],

        ),

        (

            "FS-02",

            {"logon_id": "0x9579327", "source_ip": "10.60.20.21"},

            ["windows_event_security"],

        ),

    ],

    ids=["wks-ops-vpn-logon", "fs-01-smb-logon", "fs-02-smb-logon"],

)

def test_resolve_logon_p0_a(

    tmp_path: Path,

    host: str,

    fields: dict,

    candidates: list[str],

) -> None:

    """P0-A: logon rows resolve via TargetLogonId / IpAddress and eCAR LOGIN."""

    data_root = tmp_path / "data"

    host_dir = data_root / f"{host}.colonial-energy.local"

    host_dir.mkdir(parents=True)

    (host_dir / "windows_event_security.xml").write_text(

        (

            "<Event><System><EventID>4624</EventID></System><EventData>"

            f'<Data Name="TargetLogonId">{fields["logon_id"]}</Data>'

            f'<Data Name="IpAddress">{fields["source_ip"]}</Data>'

            '<Data Name="LogonType">3</Data>'

            "</EventData></Event>\n"

        ),

        encoding="utf-8",

    )

    (host_dir / "ecar.json").write_text(

        (

            '{"object":"USER_SESSION","action":"LOGIN","src_ip":"'

            + fields["source_ip"]

            + '","logon_id":"'

            + fields["logon_id"]

            + '","logon_type":3}\n'

        ),

        encoding="utf-8",

    )

    event = _event("logon", host, fields)

    refs = _assert_observed(event, data_root, candidates)

    if "windows_event_security" in candidates:

        assert refs["windows_event_security"].endswith("#rec1")

    if "ecar" in candidates:

        assert refs["ecar"].endswith("#L1")





def test_resolve_service_installed_p0_b(tmp_path: Path) -> None:

    """P0-B: service_installed resolves via Security 4697 and eCAR SERVICE.CREATE."""

    data_root = tmp_path / "data"

    host_dir = data_root / "FS-01.colonial-energy.local"

    host_dir.mkdir(parents=True)

    (host_dir / "windows_event_security.xml").write_text(

        (

            "<Event><System><EventID>4697</EventID></System><EventData>"

            '<Data Name="ServiceName">PSEXESVC</Data>'

            '<Data Name="ServiceFileName">C:\\Windows\\PSEXESVC.exe</Data>'

            "</EventData></Event>\n"

        ),

        encoding="utf-8",

    )

    (host_dir / "ecar.json").write_text(

        '{"object":"SERVICE","action":"CREATE","service_name":"PSEXESVC"}\n',

        encoding="utf-8",

    )

    fields = {"service_name": "PSEXESVC", "service_file_name": "C:\\Windows\\PSEXESVC.exe"}

    event = _event("service_installed", "FS-01", fields)

    refs = _assert_observed(

        event,

        data_root,

        ["windows_event_security", "ecar"],

    )

    assert refs["windows_event_security"].endswith("#rec1")

    assert refs["ecar"].endswith("#L1")





def test_resolve_explicit_credentials_p1_a(tmp_path: Path) -> None:

    """P1-A: explicit_credentials resolves via Security 4648 + TargetUserName."""

    data_root = tmp_path / "data"

    host_dir = data_root / "FS-01.colonial-energy.local"

    host_dir.mkdir(parents=True)

    (host_dir / "windows_event_security.xml").write_text(

        (

            "<Event><System><EventID>4648</EventID></System><EventData>"

            '<Data Name="TargetUserName">s.kim</Data>'

            '<Data Name="TargetDomainName">COLONIAL-ENERGY</Data>'

            "</EventData></Event>\n"

        ),

        encoding="utf-8",

    )

    fields = {"target_username": "COLONIAL-ENERGY\\s.kim", "target_server": "FS-01"}

    event = _event("explicit_credentials", "FS-01", fields)

    refs = _assert_observed(event, data_root, ["windows_event_security"])

    assert refs["windows_event_security"].endswith("#rec1")





def test_resolve_create_remote_thread_p1_b(tmp_path: Path) -> None:

    """P1-B: create_remote_thread resolves via Sysmon 8 and eCAR THREAD.REMOTE_CREATE."""

    data_root = tmp_path / "data"

    host_dir = data_root / "WKS-OPS-01.colonial-energy.local"

    host_dir.mkdir(parents=True)

    (host_dir / "windows_event_sysmon.xml").write_text(

        (

            "<Event><System><EventID>8</EventID></System><EventData>"

            '<Data Name="TargetImage">C:\\Windows\\System32\\lsass.exe</Data>'

            "</EventData></Event>\n"

        ),

        encoding="utf-8",

    )

    (host_dir / "ecar.json").write_text(

        '{"object":"THREAD","action":"REMOTE_CREATE","properties":{"target":"lsass.exe"}}\n',

        encoding="utf-8",

    )

    fields = {"target_process": "C:\\Windows\\System32\\lsass.exe"}

    event = _event("create_remote_thread", "WKS-OPS-01", fields)

    refs = _assert_observed(event, data_root, ["windows_event_sysmon", "ecar"])

    assert refs["windows_event_sysmon"].endswith("#rec1")

    assert refs["ecar"].endswith("#L1")

