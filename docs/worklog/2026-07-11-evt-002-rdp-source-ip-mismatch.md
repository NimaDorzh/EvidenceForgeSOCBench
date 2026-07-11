# evt-002 RDP source IP mismatch (Colonial Pipeline)

**Date:** 2026-07-11  
**Scope:** Colonial `evt-002#0` (`rdp_session`, WKS-OPS-01, seed=42)  
**Symptom:** Resolved telemetry attributes RDP transport to `10.60.20.13`
(WKS-03), not the scenario-intended VPN-GW (`10.60.10.10`).

## Storyline intent (scenario.yaml)

| Field | Value |
|---|---|
| Step | `evt-002` (+18m) |
| Target system | `WKS-OPS-01` |
| Event | `rdp_session` |
| Declared `source_ip` | `10.60.10.10` (VPN-GW-01) |
| Narrative | RDP pivot from VPN concentrator to operations workstation |

## GROUND_TRUTH.json (emitted attack records)

No emitted storyline record on **WKS-03** or with IP `10.60.20.13` at
`2024-06-03T08:18:*Z`.

| record_id | kind | system | ts | attributes |
|---|---|---|---|---|
| `evt-002#0` | `rdp_session` | WKS-OPS-01 | 08:18:27Z | `dst_ip=10.60.20.21`, `dst_port=3389`, `uid=CH7V23…` (no `source_ip`) |
| `evt-002#1` | `process` | WKS-OPS-01 | 08:18:29Z | nltest |
| `evt-002#2` | `process` | WKS-OPS-01 | 08:18:32Z | net view |

WKS-03 in scenario topology is a normal executive workstation (`r.patel`,
`10.60.20.13`) — **not** a declared jump host or storyline node.

## Resolved telemetry (canonical backfill sources)

| Source | Ref | Client / orig | Target |
|---|---|---|---|
| Security 5156 | `#rec46` | `SourceAddress=10.60.20.13` | `DestAddress=10.60.20.21:3389` |
| Security 4624 T10 | `#rec47` | `IpAddress=::ffff:10.60.20.13`, `WorkstationName=WKS-03` | WKS-OPS-01 |
| eCAR FLOW | `#L68` | `src_ip=10.60.20.13` | `dst_ip=10.60.20.21:3389` |
| Zeek conn | `#L450` | `id.orig_h=10.60.20.13` | `id.resp_h=10.60.20.21:3389` |

## Verdict

**Generator artifact** (local EF RDP bundle / session attribution), analogous in
impact to `evt-007#1` ssl/port mismatch — not a planned Colonial pivot.

## SOC-bench impact

- **Fox `o1_scale` stage 0:** No verifiable edge VPN-GW ↔ WKS-OPS (WKS-03 not
  in affected-host set) → `campaign_scale` with two unconnected vertices. Correct
  per graph rules on **observable** fields, but does **not** validate the
  narrative VPN→OPS pivot until EF emits consistent client IP / jump semantics.
- **Capture/truth:** `source_ip` backfilled from resolved refs only (not scenario
  YAML). Do not treat Colonial stage-0 scale label as storyline pivot ground
  truth.

## Reproduction

```bash
uv run socbench capture --bundle scenarios/colonial-pipeline \
  --scenario scenarios/colonial-pipeline/scenario.yaml --seed 42
# Inspect EVID-cdf56f97 fields.source_ip and Security rec47 WorkstationName
```
