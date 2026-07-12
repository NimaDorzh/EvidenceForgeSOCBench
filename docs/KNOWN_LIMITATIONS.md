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

## Fox empty early stages when `--window-start` precedes events (fixed 2026-07-12)

**Symptom (pre-fix):** `truth build` with scenario `time_window.start` earlier
than the first canonical event (e.g. retail at `05:00Z` vs first event
`15:29Z`) crashed in `build_fox_manifest` with `ValueError: min() iterable
argument is empty`.

**Fix:** Empty cumulative slices skip first-event updates; CLI emits an
alignment warning. See `docs/worklog/2026-07-12-fox-empty-early-stages.md`.

