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


def test_resolve_linux_connection_ecar_p2_a(tmp_path: Path) -> None:
    """P2-A: Linux connection resolves eCAR FLOW by dst tuple."""
    data_root = tmp_path / "data"
    host_dir = data_root / "VPN-GW-01.colonial-energy.local"
    host_dir.mkdir(parents=True)
    (host_dir / "ecar.json").write_text(
        (
            '{"object":"FLOW","action":"CONNECT","properties":{"src_ip":"198.18.50.33",'
            '"dst_ip":"10.60.10.10","dst_port":"1194"}}\n'
        ),
        encoding="utf-8",
    )
    fields = {"dst_ip": "10.60.10.10", "dst_port": 1194, "uid": "CiMxFEIvpLA9eIYzXQ"}
    event = _event("connection", "VPN-GW-01", fields)
    refs = _assert_observed(event, data_root, ["ecar"])
    assert refs["ecar"].endswith("#L1")


def test_resolve_ssh_session_ecar_and_syslog_p2_a(tmp_path: Path) -> None:
    """P2-A: ssh_session resolves eCAR LOGIN(ssh) and syslog Accepted line."""
    data_root = tmp_path / "data"
    host_dir = data_root / "VPN-GW-01.colonial-energy.local"
    host_dir.mkdir(parents=True)
    (host_dir / "ecar.json").write_text(
        (
            '{"object":"FLOW","action":"CONNECT","properties":{"src_ip":"198.18.50.33",'
            '"dst_ip":"10.60.10.10","dst_port":"22"}}\n'
        ),
        encoding="utf-8",
    )
    (host_dir / "syslog.log").write_text(
        "Jun  3 08:02:46 vpn sshd[1200]: Accepted password for t.morgan from 198.18.50.33 port 55123 ssh2\n",
        encoding="utf-8",
    )
    fields = {
        "dst_ip": "10.60.10.10",
        "dst_port": 22,
        "source_ip": "198.18.50.33",
        "actor": "t.morgan",
    }
    event = _event("ssh_session", "VPN-GW-01", fields)
    refs = _assert_observed(event, data_root, ["ecar", "syslog"])
    assert refs["ecar"].endswith("#L1")
    assert refs["syslog"].endswith("#L1")


@pytest.mark.parametrize(
    ("dst_ip", "dst_port", "line"),
    [
        (
            "203.0.113.88",
            21,
            "%ASA-6-302014: Teardown TCP connection 99 for outside:10.60.30.40/51234 to outside:203.0.113.88/21 duration 0:01:00 bytes 524288000\n",
        ),
        (
            "203.0.113.90",
            443,
            "%ASA-6-302013: Built outbound TCP connection 100 for outside:10.60.30.40/49811 to outside:203.0.113.90/443\n",
        ),
    ],
    ids=["exfil-ftp-teardown", "exfil-https-built"],
)
def test_resolve_asa_exfil_p2_b(
    tmp_path: Path,
    dst_ip: str,
    dst_port: int,
    line: str,
) -> None:
    """P2-B: ASA exfil lines resolve by dst_ip + dst_port."""
    data_root = tmp_path / "data"
    asa_dir = data_root / "ASA-PERIM-01"
    asa_dir.mkdir(parents=True)
    (asa_dir / "cisco_asa.log").write_text(line, encoding="utf-8")
    fields = {"dst_ip": dst_ip, "dst_port": dst_port}
    event = _event("connection", "FTP-01", fields)
    refs = _assert_observed(event, data_root, ["cisco_asa"])
    assert refs["cisco_asa"].endswith("#L1")


def test_resolve_rdp_session_security_and_ecar_p2(tmp_path: Path) -> None:
    """P2: rdp_session resolves Security 4624 Type 10 (uid-correlated) and eCAR FLOW :3389."""
    data_root = tmp_path / "data"
    host_dir = data_root / "WKS-OPS-01.colonial-energy.local"
    zeek_dir = data_root / "zeek"
    host_dir.mkdir(parents=True)
    zeek_dir.mkdir(parents=True)
    (zeek_dir / "conn.json").write_text(
        (
            '{"uid":"CH7V23vussAlqjAUFr","id.orig_h":"10.60.20.13","id.orig_p":51234,'
            '"id.resp_h":"10.60.20.21","id.resp_p":3389,"service":"rdp"}\n'
        ),
        encoding="utf-8",
    )
    (host_dir / "windows_event_security.xml").write_text(
        (
            "<Event><System><EventID>4624</EventID></System><EventData>"
            '<Data Name="TargetLogonId">0xd584673</Data>'
            '<Data Name="IpAddress">::ffff:10.60.20.13</Data>'
            '<Data Name="LogonType">10</Data>'
            "</EventData></Event>\n"
        ),
        encoding="utf-8",
    )
    (host_dir / "ecar.json").write_text(
        (
            '{"object":"FLOW","action":"CONNECT","properties":{"src_ip":"10.60.20.13",'
            '"dst_ip":"10.60.20.21","dst_port":"3389"}}\n'
        ),
        encoding="utf-8",
    )
    fields = {
        "dst_ip": "10.60.20.21",
        "dst_port": 3389,
        "uid": "CH7V23vussAlqjAUFr",
        "logon_id": "0xd584673",
        "source_ip": "10.60.20.13",
    }
    event = _event("rdp_session", "WKS-OPS-01", fields, record_id="evt-002#0")
    refs = _assert_observed(event, data_root, ["windows_event_security", "ecar"])
    assert refs["windows_event_security"].endswith("#rec1")
    assert refs["ecar"].endswith("#L1")


@pytest.mark.skipif(
    not (COLONIAL_BUNDLE / "data").is_dir() or not any((COLONIAL_BUNDLE / "data").iterdir()),
    reason="colonial-pipeline data bundle not present",
)
def test_colonial_capture_resolver_integration() -> None:
    """End-to-end colonial capture: resolver debt rows should gain refs."""
    import yaml

    from evidenceforge.models.scenario import Scenario
    from socbench.capture.canonical_events import build_canonical_events

    scenario = Scenario.model_validate(
        yaml.safe_load(COLONIAL_SCENARIO.read_text(encoding="utf-8"))
    )
    events = build_canonical_events(COLONIAL_BUNDLE, scenario, seed=42)
    by_id = {event.evidence_id: event for event in events}

    expected_observed = {
        "EVID-fbf02f4b",
        "EVID-4c135d52",
        "EVID-7f8d5ad1",
        "EVID-79f30f0a",
        "EVID-03ddf851",
        "EVID-c0b7909b",
        "EVID-cdf56f97",
    }
    for evidence_id in expected_observed:
        event = by_id[evidence_id]
        assert event.observation_status == "observed", evidence_id
        assert event.output_refs, evidence_id

    assert by_id["EVID-6bdaf0d3"].observation_status == "partial"
    assert by_id["EVID-5cbc8381"].observation_status == "partial"
    assert "ecar" in by_id["EVID-5cbc8381"].unresolved_sources

    observed_count = sum(1 for event in events if event.observation_status == "observed")
    unobserved_count = sum(1 for event in events if event.observation_status == "unobserved")
    assert observed_count >= 16
    assert unobserved_count == 0
