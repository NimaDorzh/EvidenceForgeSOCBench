# SOC-bench known limitations (audit EXPECTED-A)

Short reference for partial canonical events that are **expected** under current
EvidenceForge observation profiles and SOC-bench resolver scope. Future audits
should not re-investigate these as resolver bugs unless manifests or DP4 policy
change.

## eCAR dropped by manifest (DP4)

**Example:** `EVID-79379b3d` (`evt-006a#0`, FS-01 `process`, seed=42).

- **Symptom:** `observation_status=partial`, `unresolved_sources` includes `ecar`.
- **Cause:** `OBSERVATION_MANIFEST.json` records `dropped: N` for eCAR on that
  host/event class. The process is visible in Security/Sysmon but intentionally
  absent from eCAR output.
- **Resolver scope:** Not fixable in `output_refs.py`; this is a visibility gap,
  not a missing matcher.

## Boot-time system processes outside generation window (eCAR lifecycle)

**Example:** `EVID-57bc5431` (`evt-003#1`, WKS-OPS-01 `create_remote_thread`
into `lsass.exe`, seed=42).

- **Symptom:** Sysmon Event 8 resolves; eCAR `THREAD.REMOTE_CREATE` does not.
- **Cause:** Target `lsass.exe` (PID 3864) is a boot-time system process whose
  eCAR `PROCESS` lifecycle was not modeled inside the generation window. eCAR
  cannot attach thread telemetry without a durable process row.
- **Resolver scope:** Not fixable without EF lifecycle modeling or relaxing
  eCAR correlation requirements.

## GT/service mismatch — local EF generation bug (not resolver)

**Example:** `EVID-5cbc8381` (`evt-007#1`, FTP-01 HTTPS exfil, seed=42).

- **Symptom:** Scenario/GT claim `dst_port=443`, `service=ssl`; Zeek/ASA/eCAR
  data show `resp_p=80`, `service=http` for the same Zeek UID
  (`C5YtR44NxGf2T3IjXN`).
- **Scope audit:** Colonial `evt-001#0` (`ssl:1194`) and other bundles confirm EF
  can emit TLS correctly; the defect is **local to this storyline exfil step**,
  not a global inability to model `service: ssl`.
- **Resolver scope:** Partial is correct — refs cannot claim eCAR `:443` when data
  shows `:80`. See `docs/worklog/2026-07-11-evt-007-ssl-port-mismatch.md` for
  reproduction and workaround (`service: http`, `dst_port: 80` in scenario).

## RDP client IP mismatch — local EF generation bug (not resolver)

**Example:** `EVID-cdf56f97` (`evt-002#0`, WKS-OPS-01 RDP pivot, seed=42).

- **Symptom:** Scenario declares RDP `source_ip=10.60.10.10` (VPN-GW-01);
  Security/eCAR/Zeek refs show client `10.60.20.13` (`WorkstationName=WKS-03`).
- **GROUND_TRUTH:** No emitted attack record on WKS-03 at `08:18Z`; WKS-03 is a
  normal workstation, not a storyline jump host.
- **Cause:** EF RDP/session generation attributes transport to the wrong
  internal client IP (similar class of defect to `evt-007#1`).
- **Fox impact:** Stage-0 `o1_scale=campaign_scale` (two hosts, no verifiable
  edge) is correct on observable backfill but **must not** be read as validating
  the narrative VPN→OPS pivot.
- **Details:** `docs/worklog/2026-07-11-evt-002-rdp-source-ip-mismatch.md`

## Colonial declared-vs-observed audit (2026-07-11)

Systematic comparison of all 13 storyline steps: 29 explicit field checks, 4
canonical mismatches (`evt-002` source_ip, `evt-007` service/orig_bytes), plus
2 N/A backfill/sensor gaps. Tiger-critical transitions (003→004, 004→004b,
005→005b, 006a→006b) **fail verifiable-edge tests** on observed canonical fields
(ppid absent, distinct logon_ids, distinct PIDs). Full table:
`docs/worklog/2026-07-11-declared-vs-observed-colonial.md`.

**Tiger implication:** verifiable graph must be built from observed canonical
fields only; storyline YAML is contextual, not authoritative topology.

## Tiger `sequential_tools_same_host` density (fixed 2026-07-12)

**Symptom (pre-fix):** On dense single-host scenarios (e.g. retail-test, 22 events
on `MUSIC-SRV-01`), the rule linked most within-window process pairs on the same
host (~173 contextual edges, near C(n,2)), diluting GED signal.

**Fix:** Per-host temporal chain — each process links to at most the next 3
successors within a 15-minute window (linear growth). See
`docs/worklog/2026-07-12-tiger-sequential-tools-density.md`.

**Remaining edge case:** `lateral_shared_source_ip` still pairs logon events
sharing a source IP across hosts; usually low volume on multi-host scenarios.

## Interactive WorldState replan evidence_id instability (future work)

**Scope:** optional interactive containment mode (`WorldState.apply` +
`replan_tail` with EF re-run) is **not implemented in v1**. Static mode uses
`StaticWorldState` where `apply` is a no-op and `replan_tail` returns the
unchanged tail slice.

**Known complication for future interactive mode:** a deterministic EF re-run on
a patched `scenario.yaml` will regenerate tail canonical events with new
`evidence_id` values. Downstream truth manifests, `__grader_metadata.linked_evidence_ids`,
and Tiger/Panda stage slices would all need an explicit **evidence-id stability
policy** (for example stage-prefixed ids plus relinking of pre-intervention
records). This is documented as future work; do not assume tail ids are stable
across replans until that policy lands.

See `docs/design/interactive-world-state.md`.

## Network domain: Zeek/flow-canonical (no raw PCAP in v1)

SOC-bench agent datasets expose network evidence as **Zeek/flow NDJSON**
(`siem` alerts reference `zeek_conn`; EF bundle `conn.json` remains the
canonical network source). This is an intentional deviation from the paper's
Mouse/Tiger wording that assumes a raw `.pcap`.

**Why:** reconstructing PCAP from conn metadata (for example via scapy) produces
detectable synthetic artifacts — malformed TCP handshakes, template TLS
ClientHello blobs, and unrealistic inter-packet timing. Agents trained on those
artifacts learn generator fingerprints instead of incident anomalies, violating
DP1 (realism / indistinguishability from production data).

**Future work (out of v1 scope):** if raw PCAP becomes a hard acceptance
requirement, generate it only by running real network daemons in a
containerized topology at EF generation time — not by post-hoc metadata
reconstruction. See `docs/worklog/2026-07-12-native-host-logs.md`.

## Native host-log binaries (EVTX / journal)

SOC-bench can emit native Windows `.evtx` and Linux `.journal` artifacts from
EF text sources (`windows_event_security.xml`, RFC5424 `syslog.log`). Text
sources are stage-sliced first, then converted per `agent/stage_XX/` directory
because EVTX and journal containers cannot be safely re-sliced at the binary
layer.

**External tooling:**

| Dependency | Role | Verified |
|------------|------|----------|
| `lxml`, `python-evtx` | EVTX encode/read-back tests | ✅ (`uv sync --extra binary-formats`) |
| Docker Desktop ≥28.x (running daemon) | Journal import via `quay.io/fedora/fedora:40` | ✅ 28.5.1 (2026-07-12) |
| WSL + `systemd-journal-remote` | Journal fallback backend | ⚠️ Optional; not verified on this host |
| Windows `wevtutil qe` | Optional EVTX cross-check | ✅ Win11 26200 |
| Chainsaw | Optional manual EVTX validation | ❌ Not installed |

| Artifact | Conversion | Verification |
|----------|------------|--------------|
| `.evtx` | Pure Python encoder (`socbench.raw`, derived from JPCERT `xml2evtx`) | `python-evtx` round-trip tests; optional [Chainsaw](https://github.com/WithSecure/chainsaw) CLI |
| `.journal` | Journal Export Format → `systemd-journal-remote` via Docker (preferred) or WSL | `journalctl --file` round-trip tests |

Install optional Python deps: `uv sync --extra binary-formats`. Journal
conversion requires a **running Docker daemon** (Fedora 40 image) or WSL with
`systemd-journal-remote`. CI without these backends skips
`@pytest.mark.binary_formats` journal tests.

Deliverable paths are under `dataset/agent/stage_XX/data/<host>/`; `_staging/`
is build-time scratch space only and is removed before `MANIFEST.json` is written.

**Windows note:** modern `wevtutil` no longer imports arbitrary Event Viewer XML
into live channels on all builds. SOC-bench therefore uses the vendored
`xml2evtx` encoder instead of `wevtutil im` so conversion stays reproducible
without admin privileges.


**Symptom (pre-fix):** `truth build` with scenario `time_window.start` earlier
than the first canonical event (e.g. retail at `05:00Z` vs first event
`15:29Z`) crashed in `build_fox_manifest` with `ValueError: min() iterable
argument is empty`.

**Fix:** Empty cumulative slices skip first-event updates; CLI emits an
alignment warning. See `docs/worklog/2026-07-12-fox-empty-early-stages.md`.

