# EF local bug: colonial evt-007#1 claims HTTPS :443, data is HTTP :80

**Date:** 2026-07-11  
**Bundle:** `scenarios/colonial-pipeline`  
**Seed:** 42  
**Canonical:** `EVID-5cbc8381` (`record_id=evt-007#1`, `kind=connection`)

## Summary

Storyline step `evt-007` event index 1 models secondary exfiltration as HTTPS to
`203.0.113.90:443` with `service: ssl` and hostname `cdn-pipeline-updates.com`.
Generated Zeek, ASA, and eCAR artifacts for UID `C5YtR44NxGf2T3IjXN` use
**destination port 80** and **service `http`**, not 443/ssl.

This is a **local EvidenceForge generation defect** for this exfil connection,
not a SOC-bench resolver gap and not proof that EF cannot model TLS globally.

## Reproduction

```bash
eforge generate --force --output scenarios/colonial-pipeline --seed 42
```

Scenario intent (`scenarios/colonial-pipeline/scenario.yaml`, `evt-007` events[1]):

```yaml
dst_ip: "203.0.113.90"
dst_port: 443
service: ssl
hostname: "cdn-pipeline-updates.com"
```

Observed data (same UID across sources):

| Source | Path | Actual tuple / service |
|--------|------|------------------------|
| Zeek | `data/ZEEK-PERIM-TAP/conn.json` (uid `C5YtR44NxGf2T3IjXN`) | `id.resp_p`: **80**, `service`: **http** |
| ASA | `data/ASA-PERIM-01/cisco_asa.log` | teardown/built lines reference **/80** |
| eCAR | `data/FTP-01.colonial-energy.local/ecar.json` | `dst_port`: **80** (no :443 row) |

## Scope audit (not systemic)

Connection port audit across colonial + reference bundles:

| Bundle | Connection events claiming ssl/443 | Zeek confirms :443? |
|--------|-----------------------------------|---------------------|
| colonial-pipeline | `evt-007#1` only | **No** — Zeek :80/http |
| colonial-pipeline | `evt-001#0` (`ssl`, port 1194 OpenVPN) | **Yes** — match |
| colonial-pipeline | `evt-007#0` (`ftp:21`) | **Yes** — match |
| retail-test | none with ssl/443 | n/a (only ftp:21) |
| branch-office-test | no connection storyline events | n/a |

**Conclusion:** EF can emit SSL/TLS (`evt-001#0` proves it). The bug is tied to
the HTTPS exfil storyline generator path for `evt-007#1`, likely plaintext HTTP
modeling despite `service: ssl` in YAML.

## SOC-bench impact

- `EVID-5cbc8381` correctly stays **`partial`**: `ecar` is in `unresolved_sources`
  because no eCAR FLOW row exists for `dst_port=443`.
- Resolver should **not** map this to `:80` refs while canonical fields still
  claim `:443` — that would hide the GT/data mismatch.

## Workarounds (fork / scenario)

1. **Scenario alignment (recommended for capture pass):** change `evt-007#1` to
   `dst_port: 80`, `service: http`, and update GROUND_TRUTH expectations to
   match what EF actually generates until the engine bug is fixed upstream.
2. **Upstream EF fix:** ensure exfil `connection` events with `service: ssl` and
   `dst_port: 443` allocate TLS transport (or explicit proxy tunnel) rather than
   plaintext HTTP on port 80.

Diagnostic helper: `scripts/_audit_connection_ports.py` (connection port audit).
