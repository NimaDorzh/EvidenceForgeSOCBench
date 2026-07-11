# Colonial declared-vs-observed audit (13 storyline steps)

**Date:** 2026-07-11  
**Bundle:** `scenarios/colonial-pipeline`, seed=42  
**Method:** Compare explicit fields in `scenario.yaml` per storyline sub-event
against canonical `fields` after `backfill_fields_from_output_refs`.  
**Scripts:** `scripts/_audit_declared_vs_observed.py`,
`scripts/_audit_tiger_correlations.py`.

## Summary table (29 explicit field comparisons)

| step | record | kind | field | declared | observed (canonical) | match | known? |
|---|---|---|---|---|---|---|---|
| evt-001 | evt-001#0 | connection | source_ip | 198.18.50.33 | 198.18.50.33 | Y | — |
| evt-001 | evt-001#0 | connection | dst_ip | 10.60.10.10 | 10.60.10.10 | Y | — |
| evt-001 | evt-001#0 | connection | dst_port | 1194 | 1194 | Y | — |
| evt-001 | evt-001#0 | connection | service | ssl | ssl | Y | — |
| evt-001 | evt-001#1 | ssh_session | source_ip | 198.18.50.33 | 198.18.50.33 | Y | — |
| evt-002 | evt-002#0 | rdp_session | source_ip | 10.60.10.10 | 10.60.20.13 | **N** | KNOWN — evt-002 worklog |
| evt-004b | evt-004b#0 | service_installed | service_name | PSEXESVC | PSEXESVC | Y | — |
| evt-004b | evt-004b#0 | service_installed | service_file_name | C:\Windows\PSEXESVC.exe | C:\Windows\PSEXESVC.exe | Y | — |
| evt-005 | evt-005#0 | explicit_credentials | source_ip | 10.60.20.21 | *(absent)* | N/A | backfill gap (4648) |
| evt-005 | evt-005#0 | explicit_credentials | target_username | COLONIAL-ENERGY\s.kim | COLONIAL-ENERGY\s.kim | Y | — |
| evt-005 | evt-005#0 | explicit_credentials | target_server | FS-01 | FS-01 | Y | — |
| evt-005 | evt-005#1 | logon | source_ip | 10.60.20.21 | 10.60.20.21 | Y | — |
| evt-005 | evt-005#1 | logon | logon_type | 3 | 3 | Y | — |
| evt-005b | evt-005b#0 | logon | source_ip | 10.60.20.21 | 10.60.20.21 | Y | — |
| evt-005b | evt-005b#0 | logon | logon_type | 3 | 3 | Y | — |
| evt-006b | evt-006b#0 | connection | dst_ip | 10.60.30.40 | 10.60.30.40 | Y | — |
| evt-006b | evt-006b#0 | connection | dst_port | 21 | 21 | Y | — |
| evt-006b | evt-006b#0 | connection | service | ftp | *(absent)* | N/A | Zeek filtered (DP4) |
| evt-007 | evt-007#0 | connection | source_ip | 10.60.30.40 | 10.60.30.40 | Y | — |
| evt-007 | evt-007#0 | connection | dst_ip | 203.0.113.88 | 203.0.113.88 | Y | — |
| evt-007 | evt-007#0 | connection | dst_port | 21 | 21 | Y | — |
| evt-007 | evt-007#0 | connection | service | ftp | ftp | Y | — |
| evt-007 | evt-007#0 | connection | orig_bytes | 524288000 | 540722640 | **N** | measurement variance |
| evt-007 | evt-007#1 | connection | source_ip | 10.60.30.40 | 10.60.30.40 | Y | — |
| evt-007 | evt-007#1 | connection | dst_ip | 203.0.113.90 | 203.0.113.90 | Y | — |
| evt-007 | evt-007#1 | connection | dst_port | 443 | 443 *(GT)* / **80** *(Zeek)* | **Y†** | KNOWN — evt-007 worklog |
| evt-007 | evt-007#1 | connection | service | ssl | http | **N** | KNOWN — evt-007 worklog |
| evt-007 | evt-007#1 | connection | orig_bytes | 262144000 | 272573043 | **N** | measurement variance |
| evt-007 | evt-007#1 | connection | hostname | cdn-pipeline-updates.com | *(absent)* | N/A | not in GT/backfill |

**† Hidden mismatch:** canonical still carries GT `dst_port=443` because backfill
does not override populated GT fields; Zeek telemetry alone shows `:80/http`.

Steps **without** explicit topology fields in YAML (no rows): evt-002#1/#2,
evt-003, evt-004, evt-006a, evt-008, evt-009a, evt-009b — compare N/A at this
layer (process/command semantics only).

## Tiger-critical verifiable edges (forensics 2026-07-11)

| transition | narrative expectation | forensics verdict | Tiger class |
|---|---|---|---|
| evt-003 → evt-004 | parent/child | Sibling ppid=5464 (PowerShell); ppid=5496 not parent of 5508. Sysmon has ppid; canonical omits (capture gap). **Not EF bug.** | **contextual** |
| evt-004 → evt-004b | same binary | PsExec launcher + PSEXESVC on target — **verifiable by pattern**, not filename match | **verifiable** |
| evt-005 → evt-005b | shared session | Different LogonIDs per target server — **correct SMB behavior**, not evt-002-class | **contextual** |
| evt-006a → evt-006b | same PID | **Multi-process by design** in scenario.yaml; link via `stage-fs01.zip` | **verifiable** (file rules) |

Details: `docs/worklog/2026-07-11-tiger-verifiable-rules-colonial.md`.

## New vs known findings

| finding | classification | action |
|---|---|---|
| evt-002 RDP source_ip | **Known EF local bug** | `KNOWN_LIMITATIONS.md`, evt-002 worklog |
| evt-007#1 ssl→http / :443→:80 | **Known EF local bug** | `KNOWN_LIMITATIONS.md`, evt-007 worklog |
| evt-007 orig_bytes drift (~4%) | **Expected measurement variance** | Zeek byte accounting ≠ scenario round targets; not EF topology bug |
| evt-007#1 dst_port Y with Zeek :80 | **Capture limitation** | GT poisons field before backfill; audit must cross-check Zeek refs |
| evt-005#0 missing source_ip | **SOC-bench backfill gap** | 4648 matcher does not backfill `source_ip` yet |
| evt-006b missing service | **DP4 / sensor gap** | Zeek conn filtered; not declared-vs-observed EF bug |
| Tiger ppid in canonical | **Capture backfill gap** (ppid in Sysmon/eCAR, not canonical) | Extend backfill or Tiger reads refs directly in v2 |
| Tiger 003→004 / 005→005b | **Plan overreach, not EF bug** | Corrected verifiable rules in PLAN 3d |

No **new** EF local bugs beyond evt-002 and evt-007#1.

## Conclusion for Tiger

**Do not trust declared storyline topology as soft ground truth** for verifiable
edges. Observable canonical fields (after backfill, with Zeek cross-check when GT
may be wrong) are the only safe source for Tiger's hard core.

Narrative YAML remains useful for **authoring** and **contextual** edges, but
Fox stage-0 already showed VPN→OPS pivot is not telemetry-validated. The same
applies to PsExec parentage, shared LogonID lateral continuity, and staging→FTP
PID reuse — all fail on observed fields today.

**Recommended Tiger policy:** build verifiable edges strictly from observed
canonical + confirmed `output_refs` rows; mark narrative-only links as
`edge_class: contextual`.
