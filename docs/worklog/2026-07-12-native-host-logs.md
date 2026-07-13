# Native host-log conversion (Step 7)

Date: 2026-07-12

## Goal

Emit native host artifacts for SOC-bench agent datasets:

1. `windows_event_security.xml` → `windows_event_security.evtx`
2. RFC5424 `syslog.log` → `system.journal`

Network evidence remains **Zeek/flow-canonical**; scapy PCAP reconstruction is
explicitly out of scope (see `docs/KNOWN_LIMITATIONS.md`).

## Environment (verification run)

| Tool | Status |
|------|--------|
| Windows `wevtutil qe` | ✅ Used for EVTX round-trip field compare (`EventRecordID`) |
| Docker Desktop | ✅ Daemon `28.5.1` (Server `28.5.1`, Linux engine) |
| Journal backend | ✅ Docker + `quay.io/fedora/fedora:40` (`systemd-journal-remote` at `/usr/lib/systemd/`) |
| WSL Ubuntu 24.04 | Available; `systemd-journal-remote` **not** installed (sudo blocked in CI-like shell) |
| Chainsaw | ❌ Not on PATH (optional manual EVTX check only) |

## Design decisions

### Stage gating

Binary EVTX/journal files cannot be sliced safely after creation. Pipeline:

1. Copy EF host text logs into staging `data/<host-fqdn>/`
2. `bucketize_host_logs()` writes cumulative text slices to `_staging/agent_raw/stage_XX/data/`
3. `convert_staged_host_logs()` converts per-stage text to `.evtx`/`.journal` and
   removes text intermediates
4. `export_agent_tree(agent_raw, dataset/agent)` copies the staged tree to the
   deliverable agent path (binaries via `shutil.copy2`; NDJSON via DP2 gate)
5. `shutil.rmtree(_staging)` then `write_manifest()` — staging is **not** part of
   the shipped dataset or MANIFEST

### EVTX encoder

Uses vendored JPCERT `xml2evtx` logic in `src/socbench/raw/_xml2evtx.py` (BSD-3).
Round-trip verification uses `python-evtx` + field compare on `EventRecordID`,
`EventID`, `Computer`, `TimeCreated`.

### Journal backend

RFC5424 syslog is rendered to **systemd Journal Export Format** (requires
`_BOOT_ID`, `__REALTIME_TIMESTAMP`, etc.) and imported by
`systemd-journal-remote` inside Docker (`quay.io/fedora/fedora:40`) or WSL.
Read-back uses `journalctl --file -o json`.

## Verification evidence

### Pytest (2026-07-12)

```text
pytest tests/socbench/test_binary_formats.py -m binary_formats --no-cov
→ 5 passed, 1 skipped (slow colonial convert integration test)

pytest tests/socbench/test_export.py::test_manifest_excludes_staging_and_paths_exist --no-cov
→ 1 passed
```

Journal round-trip test (`test_journal_roundtrip_fixture_fields_match`) **executed**
(not skipped) with field compare on: `priority`, `timestamp`, `hostname`,
`appname` (`SYSLOG_IDENTIFIER`), `message` (`MESSAGE`).

### Fixture round-trip (record[0])

| Field | syslog.log | `.journal` (journalctl JSON) |
|-------|------------|------------------------------|
| priority | `6` | `6` |
| timestamp | `2026-03-15T10:15:00.000000Z` | `2026-03-15T10:15:00.000000Z` |
| hostname | `SRV-WEB-01` | `SRV-WEB-01` |
| appname | `sshd` | `sshd` |
| message | `Accepted publickey for admin from 10.0.10.50 port 54321 ssh2` | match |

### Colonial build (`--native-host-logs`, seed 42)

```bash
python -m socbench build --scenario scenarios/colonial-pipeline/scenario.yaml \
  --seed 42 --tasks fox,goat,mouse,tiger,panda --stream-by-stage \
  --window-start 2024-06-03T08:00:00Z --out ./dataset/ --native-host-logs
```

- 90 staged host logs converted (EVTX + journal)
- Deliverable journals: `dataset/agent/stage_XX/data/{FTP-01,VPN-GW-01}.colonial-energy.local/system.journal`
  (12 files across 6 stages)
- Manual read:

```bash
docker run --rm -v .../dataset/agent/stage_00/data/VPN-GW-01.colonial-energy.local:/work \
  quay.io/fedora/fedora:40 bash -lc \
  'dnf install -y -q systemd >/dev/null; journalctl --file=/work/system.journal --no-pager -n 3'
```

Sample output (colonial VPN-GW-01 stage_00):

```text
Jun 03 08:29:09 VPN-GW-01 irqbalance[14933]: NUMA node 1: balancing pass complete, 1 IRQs moved
Jun 03 08:29:09 VPN-GW-01 dbus-daemon[29588]: [system] Activating via systemd: ...
Jun 03 08:29:29 VPN-GW-01 irqbalance[14933]: NUMA node 0: balancing pass complete, 1 IRQs moved
```

`python -m socbench validate ./dataset/` → passed.

### DP2 / grader leakage

Colonial EF host sources (`windows_event_security.xml`, `syslog.log`) contain no
`phase`, `attack`, `actor`, `evidence_id`, or `min_stage_gate` fields. Native
binaries bypass NDJSON DP2 stripping (`shutil.copy2`); grader metadata was never
present in the source format.

## Bug fixed during verification

`write_manifest()` previously ran **before** `shutil.rmtree(_staging)`, leaving
197 ghost `_staging/...` paths in `MANIFEST.json` whose files were deleted
immediately after. Fixed by reversing the order; regression test:
`test_manifest_excludes_staging_and_paths_exist`.

## Files

- `src/socbench/raw/_xml2evtx.py`, `evtx.py`, `journal.py`, `host_logs.py`
- `tests/socbench/test_binary_formats.py`, `tests/socbench/test_export.py`

## Optional deps

```bash
uv sync --extra binary-formats
uv run pytest tests/socbench/test_binary_formats.py -m binary_formats --no-cov
```
