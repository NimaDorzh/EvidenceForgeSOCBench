# Tiger verifiable-edge forensics (Colonial, seed=42)

**Date:** 2026-07-11  
**Purpose:** Classify why four Tiger-critical transitions looked non-verifiable,
separate EF defects from plan overreach, and derive corrected verifiable rules
before `tiger.py`.

**Scripts:** `scripts/_audit_tiger_transition_forensics.py`,
`scripts/_audit_tiger_correlations.py`.

---

## 1. evt-003 → evt-004 (procdump → PsExec)

### Question
Does pid=5508 (PsExec) have ppid=5496 (procdump) anywhere in WKS-OPS-01 telemetry?

### Answer: **No — and that is correct Windows behavior**

| Process | pid | ppid (Sysmon/eCAR) | parent image | logon_id |
|---|---|---|---|---|
| procdump64 | 5496 | **5464** | powershell.exe | 0xd584673 |
| PsExec | 5508 | **5464** | powershell.exe | 0xd584673 |

Full grep for `ppid=5496` as parent of any process on WKS-OPS-01: **zero hits**.

### Classification

| Layer | Verdict |
|---|---|
| EF generation | **Not a bug.** Both tools are sibling launches from the same interactive PowerShell (5464). Real operators run sequential post-exploit tools from one shell; Windows does not make procdump the parent of PsExec. |
| Plan rule "parent→child ppid-match" | **Misapplied.** Narrative is temporal tool chain (dump creds → use creds), not a process tree edge. |
| SOC-bench capture | **Gap:** Sysmon/eCAR contain `ppid`, but canonical GT/backfill omits it for process records. Tiger cannot use ppid from canonical today without extending backfill. |
| Tiger edge class | **contextual** — shared host + shared logon_id + time ordering (~13 min). |

---

## 2. evt-004 → evt-004b (PsExec launcher → PSEXESVC service)

### Question
Is "same binary" violated because launcher is `PsExec.exe` and service is `PSEXESVC.exe`?

### Answer: **Plan wording was too strict; PsExec pair is verifiable by pattern**

| Side | Host | Observable |
|---|---|---|
| Launcher | WKS-OPS-01 | `PsExec.exe \\FS-01 -accepteula -s cmd.exe /c whoami` (pid 5508) |
| Service | FS-01 | `service_name=PSEXESVC`, `service_file_name=C:\Windows\PSEXESVC.exe` |

This matches **standard PsExec mechanics**: client binary on source, helper service binary on target. Requiring byte-identical image names would reject every real PsExec deployment.

### Classification

| Layer | Verdict |
|---|---|
| EF generation | **Correct.** |
| Plan rule | **Needs rewrite:** verifiable = `psexec_remote_service` pattern (launcher cmd references `\\TARGET` + target `PSEXESVC` service install within window), not identical filenames. |
| Tiger edge class | **verifiable** (`psexec_remote_service`) |

---

## 3. evt-005 → evt-005b (SMB lateral FS-01 → FS-02)

### Question
Two LogonIDs (`0xd19c221` vs `0x957a88f`) with same source_ip — EF session-loss bug or correct SMB auth?

### Answer: **Architecturally correct Windows behavior**

Type 3 network logons are allocated **per target server**. Lateral SMB to FS-01 and FS-02 from the same client IP naturally yields **different TargetLogonId values on each server**. This is not analogous to evt-002 (wrong client IP on one session) or evt-007 (wrong port/service on one connection).

Scenario YAML explicitly models **two separate logon events** on two systems (evt-005 / evt-005b).

### Classification

| Layer | Verdict |
|---|---|
| EF generation | **Not a bug.** |
| Plan rule "auth-session→action in same LogonID" | **Scope error:** applies **within one host/session**, not across lateral multi-target SMB burst. |
| Tiger edge class | **contextual** — shared `source_ip` + same actor + temporal proximity; **not** shared logon_id across hosts. |

---

## 4. evt-006a → evt-006b (archive → FTP upload)

### Question
Was upload intended as the same PID as the archiver?

### Answer: **No — two-step (multi-process) by design**

`scenario.yaml` declares **three separate process events**:

1. `evt-006a#0` — Compress-Archive → `stage-fs01.zip` (pid 5200)
2. `evt-006a#1` — xcopy to staging share (pid 5204)
3. `evt-006b#1` — WebClient UploadFile to FTP (pid 5296)

Activity text: *"transfers staged archive"* — file handoff, not single long-lived process.

Telemetry links via **filename** and **session**:

| Step | pid | Shared artifact | logon_id (eCAR) |
|---|---|---|---|
| archive | 5200 | `stage-fs01.zip` in cmd / GT `staged_archive` | *(eCAR partial — no PROCESS row)* |
| xcopy | 5204 | `stage-fs01.zip` in cmd | 0xd19c221 |
| upload | 5296 | `stage-fs01.zip` in UploadFile path | 0xd19c221 |

### Classification

| Layer | Verdict |
|---|---|
| EF generation | **Not a bug.** Multi-step staging is realistic. |
| Plan rule "same PID" | **Wrong rule for this storyline.** Replace with **file artifact continuity** (normalized filename/path match) optionally combined with same-host logon_id for on-host actions. |
| Tiger edge class | **verifiable** (`file_artifact_continuity` for stage-fs01.zip chain; `file_to_network` for upload + evt-006b#0 FTP connection) |

---

## Corrected verifiable rules (for PLAN 3d / tiger.py)

| Rule ID | Verifiable when | Not verifiable / contextual |
|---|---|---|
| `process_parent_child` | Same host, child canonical/sysmon ppid == parent pid | Sequential tools from same shell (sibling ppid) |
| `psexec_remote_service` | Launcher cmd has `psexec` + `\\HOST`; target host has `PSEXESVC` service_installed within window | Exact filename match PsExec.exe == PSEXESVC.exe |
| `auth_session_action` | Same **host**, same `logon_id`, later action on that host | Cross-host lateral logons (different LogonIDs expected) |
| `file_artifact_continuity` | Same normalized filename/path across process events on a host | Same PID across compress → upload |
| `file_to_network` | Process cmd references file F; connection/upload event references F within window | — |
| `host_interaction` | (reuse Fox rules) source_ip, dst_ip, remote hostname in cmd | — |

**Contextual fallback (never hard-match):** shared user/actor, shared logon_id without same-host action, temporal proximity alone, narrative-only storyline ordering.

---

## Expected Colonial verifiable skeleton (seed=42)

After rule correction, canonical-backed edges should include at least:

1. **WKS-OPS-01 → FS-01** via `psexec_remote_service` (evt-004 → evt-004b)
2. **stage-fs01.zip chain** via `file_artifact_continuity` (evt-006a#0 → #1 → evt-006b#1)
3. **Upload → FTP** via `file_to_network` (evt-006b#1 process + evt-006b#0 connection)
4. **Host interaction edges** from Fox graph rules where observable (005 source_ip, 006b FTP tuple, etc.)

**Not** in verifiable core: procdump→PsExec ppid chain; FS-01→FS-02 shared LogonID.

---

## New EF bugs?

**None** from this pass. Findings are plan-scope corrections + SOC-bench capture backfill gap (ppid not in canonical).

---

## Update 2026-07-11 (ppid backfill closed)

**Capture fix:** `backfill_fields_from_output_refs()` now pulls `pid`/`ppid` from
Sysmon Event ID 1 and eCAR `PROCESS CREATE`. Colonial seed=42 confirms ppid on
evt-003/004 (5464), evt-006a#1 (3448), etc.

**Tiger re-run:** `verifiable=6`, `contextual=8`. New edge: `file_to_network`
evt-006a#1 (xcopy) → evt-006b#0 (FTP conn).

**`process_parent_child` on Colonial:** **zero empirical instances** — rule is
valid and implemented, but this scenario has no child whose `ppid` equals another
storyline process `pid` (procdump/PsExec are siblings under PowerShell 5464;
Compress-Archive pid 5200 is not parent of xcopy ppid 3448). Not a broken rule.

---

## P0 note for paper

Tiger GED on Colonial **must not** be interpreted with an empty verifiable core — after rule correction the core is **small but non-empty** (~3–5 edges). If reviewers expect dense process-tree recovery, call out EF/capture limits explicitly in Limitations.
