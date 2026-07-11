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
