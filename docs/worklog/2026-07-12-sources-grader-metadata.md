# Worklog: Step 4 — Synthetic Sources + Augment (2026-07-12)

## Goal

Implement `src/socbench/sources/` (five synthetic sources with hidden
`__grader_metadata`) and `src/socbench/mutate/augment.py` for surface-form
robustness without changing truth-projector semantics.

## Implemented

```
src/socbench/sources/
  common.py, models.py, text.py, errors.py
  siem.py, hostmetrics.py, vss.py, helpdesk.py, cti.py
src/socbench/mutate/augment.py
tests/socbench/test_sources.py
tests/socbench/test_augment.py
```

CLI: `socbench sources build -e <canonical_events.ndjson> -b <bundle> --seed 42`

Build order matches plan milestone: siem → hostmetrics → vss → helpdesk → cti.

### Source outputs (under `<bundle>/data/`)

| Source | Path | Attack-linked via `__grader_metadata` |
|--------|------|--------------------------------------|
| siem | `siem/alerts.ndjson`, `siem/xdr_anomalies.ndjson` | Rule-matched canonical events; 8 FP rows without metadata |
| hostmetrics | `hostmetrics/{host}.ndjson` | Spike samples during encrypt/exfil windows |
| vss | `vss/{host}/shadow_ops.ndjson` + `process_telemetry/vss_duplicates.ndjson` | vssadmin delete-shadows process events |
| helpdesk | `helpdesk/tickets.ndjson` | Late user reports linked to encrypt events (not positive truth evidence) |
| cti | `cti/feeds/incident_correlation.ndjson` + 3× `trap_noise_*.ndjson` | Relevant IOC rows linked; 36 trap IOCs unlinked |

### DP4 decisions

- **hostmetrics excluded hosts:** `OT-HMI-01`, `DC-01` — documented in
  `HOSTMETRICS_EXCLUDED_HOSTS` / `hostmetrics_coverage_doc()`.
- **siem FN:** `CORR-006` (create_remote_thread) fn_rate=1.0;
  `CORR-007` (rdp_session) fn_rate=0.5 — deterministic per seed.
- **siem FP:** 8 benign noise alerts with `false_positive: true`, no grader metadata.

### Text determinism

- Default: template variants keyed by `(seed, template_id, linked_evidence_ids)`.
- Optional LLM: `LlmTextCache` on disk; uncached calls raise `UncachedLlmCallError`.

### Augment invariant (explicit test asserts)

`tests/socbench/test_augment.py`:

- `test_augment_invariant_preserves_truth_projectors_and_linked_evidence_ids`
  - **Before augment:** builds sources, snapshots all five truth manifests
    (Fox/Goat/Mouse/Tiger/Panda) and every `__grader_metadata.linked_evidence_ids`.
  - **After augment:** re-builds truth from the same canonical NDJSON (unchanged),
    re-reads linked ids from mutated source files.
  - **Asserts:**
    - `before_manifests[projector] == after_manifests[projector]` for each of
      `fox`, `goat`, `mouse`, `tiger`, `panda`.
    - `before_linked == after_linked` (all records with grader metadata).
    - helpdesk text changed (surface form mutated).
- `test_augment_preserves_grader_linked_evidence_ids` — focused re-check of linked ids only.

### UncachedLlmCallError (explicit test asserts)

`tests/socbench/test_sources.py`:

- `test_uncached_llm_call_is_blocked_when_llm_enabled_without_cache` —
  `llm_enabled=True`, `llm_cache=None` → `pytest.raises(UncachedLlmCallError)`.
- `test_uncached_llm_call_is_blocked_when_cache_exists_but_misses` —
  empty cache file, cache miss → same exception (no silent template fallback).

### Helpdesk gating contract (Step 5 handoff for `bucketize.py`)

Three field names bucketizer should consume; exact types from Pydantic models:

| Field | Location | Type | Semantics |
|-------|----------|------|-----------|
| `helpdesk_min_stage` | `SourceBuildConfig` (`sources/models.py`) | `int \| None` | Build-time override for minimum stage index. Default when `None`: `max_stage // 2` via `resolve_helpdesk_min_stage()`. Tickets are **not emitted** for encrypt events whose `stage_of(ts) < helpdesk_min_stage`. |
| `min_stage_gate` | helpdesk ticket **payload** (`helpdesk/tickets.ndjson`) | `int` | Echo of the gate value applied at build time; bucketizer can filter agent-stage exports: omit ticket when `agent_stage < min_stage_gate`. |
| `latency_applied_ms` | `__grader_metadata` on each helpdesk ticket | `int` | Milliseconds added to linked encrypt event `ts` to produce ticket `ts`. Bucketizer may use for late-source gating: ticket visible only when `agent_stage_end_ms >= encrypt_ts + latency_applied_ms`. |

Related build config (not bucketizer-facing, but documents baseline latency):

| Field | Location | Type | Default |
|-------|----------|------|---------|
| `helpdesk_base_latency_ms` | `SourceBuildConfig` | `int` | `1_800_000` (30 min) |

CLI flags already wired: `--helpdesk-min-stage`, `--stage-minutes`, `--window-start`.

### Text determinism

### CLI determinism (colonial, seed=42, window 08:00Z)

Two `socbench sources build` runs → identical per-file SHA-256 (read from disk):

| File (relative) | SHA-256 |
|-----------------|---------|
| `siem/alerts.ndjson` | `696cbc368fd0552be0671eebc3ea1e2dcd6308c11ae1397eba04f7a3c959fa94` |
| `helpdesk/tickets.ndjson` | `e7db91567217beca948a353cd13fd397a7f8527f5a9ab6c46b7680067df542cf` |
| `vss/FS-01/shadow_ops.ndjson` | `07a6007db09f3562b49be5a20e4792da79fe0a6aee1bd9e66eace2fe6b495368` |
| `cti/feeds/incident_correlation.ndjson` | `12543e89c738c7d000d6bf057cc2673035ad6831c05f6d12799490b1383e1857` |
| `hostmetrics/FS-01.ndjson` | `2f5337954efa816597d03204a37890a927c26795f0ecb1d7e04bbe92abf27b3c` |

### Fork purity

No changes under `src/evidenceforge/`.

## Next (Step 5)

- `bucketize.py` stage gating for helpdesk/CTI in agent exports using
  **`min_stage_gate`** (payload) and **`latency_applied_ms`** (grader metadata);
  build override via **`helpdesk_min_stage`** on `SourceBuildConfig`.
- DP2 export strip of `__grader_metadata` (Step 6)
