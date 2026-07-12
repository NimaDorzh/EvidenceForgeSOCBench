# Worklog: Step 6 — Dataset Export + DP2 Gate + Validate (2026-07-12)

## Goal

Implement end-to-end dataset build (`export_dataset.py`), DP2 agent export gate,
integrity signatures, and post-build validation.

## Implemented

```
src/socbench/
  export_agent.py          # DP2 strip; NO socbench.truth imports
  export_dataset.py        # full build orchestration (sources → bucketize → export)
  integrity/signatures.py  # MANIFEST.json per-file + dataset SHA-256
  validate.py              # five consistency checks + CLI hook
tests/socbench/
  test_export.py           # DP2 gate + determinism + mutate path
  test_validate.py         # per-check + aggregate validate
```

CLI:

```powershell
python -m socbench build --scenario scenarios/colonial-pipeline/scenario.yaml `
  --seed 42 --tasks fox,goat,mouse,tiger,panda --stream-by-stage `
  --window-start 2024-06-03T08:00:00Z --out ./dataset/

python -m socbench validate ./dataset/
```

Optional surface-form mutation:

```powershell
python -m socbench build ... --mutate-seed 99
```

### Dataset layout

| Path | Contents |
|------|----------|
| `agent/stage_XX/data/...` | Cumulative staged sources; DP2-clean |
| `agent/topology.json` | Scenario systems/segments (agent-visible) |
| `grader/canonical_events.ndjson` | Full canonical timeline |
| `grader/manifests/*.json` | Fox/Goat/Mouse/Tiger/Panda (+ tiger_ged_spec) |
| `grader/evidence_registry.json` | evidence_id ↔ record_id index |
| `MANIFEST.json` | SHA-256 for every artifact + dataset aggregate hash |

### DP2 gate (`export_agent.py`)

Stripped from **every** agent NDJSON row:

- `phase`, `attack`, `actor`, `evidence_id`, `observed_by`
- `__grader_metadata`, `min_stage_gate`

Also excluded from agent tree:

- `canonical_events.ndjson` (grader-only)
- any path under `grader/`

`export_agent.py` is isolated from `socbench.truth` (AST test enforces).

### DP2 test design (lesson from Step 5)

`test_dp2_gate_strips_injected_fields_from_agent_export`:

1. Builds real colonial bundle + bucketize
2. **Injects all DP2 fields** into stage_00 SIEM alert (including `min_stage_gate`)
3. Asserts fields present **before** export
4. Runs `export_agent_tree`
5. Asserts fields absent **after** export

Negative control: `test_dp2_gate_detects_injected_fields_when_export_disabled`.

### validate.py checks

1. `validate_claim_evidence_ids_resolve` — manifest evidence_ids → canonical events
2. `validate_helpdesk_not_positive_evidence` — ticket_ids ∉ manifest claims
3. `validate_dp2_agent_clean` — DP2 field / grader path scan (CLI + pytest)
4. `validate_causality_respects_stage_order` — staged claims + agent `stage_index`
5. `validate_tiger_verifiable_edges_reconstructible` — agent SIEM/VSS witnesses for
   each Tiger verifiable edge (relaxed host matching when `--mutate-seed` renames hosts)

#### Negative-test matrix (`tests/socbench/test_validate.py`)

Each invariant has a dedicated break-then-detect test (not only "clean dataset passes"):

| Check | Negative test | Break mechanism |
|-------|---------------|-----------------|
| claim resolve | `test_validate_claim_resolution_fails_on_missing_evidence_id` | inject `EVID-deadbeef` into fox stage-0 o3 |
| helpdesk exclusion | `test_validate_helpdesk_fails_when_ticket_id_claimed_as_positive_evidence` | append real `HD-*` ticket to panda `supporting_evidence_ids` |
| DP2 agent clean | `test_validate_dp2_agent_clean_fails_on_poisoned_record` | inject `__grader_metadata` into agent SIEM row |
| causality / stage order | `test_validate_causality_fails_when_future_evidence_claimed_in_early_stage` | append max-stage `EVID-*` to panda stage-0 claims |
| Tiger verifiable edges | `test_validate_tiger_fails_when_psexec_edge_not_witnessed_in_agent` | delete all `CORR-002` SIEM rows from agent |
| aggregate CLI | `test_validate_dataset_aggregate_fails_when_any_invariant_breaks` | inject agent `evidence_id` field |

**Bug fixed during negative-test audit:** helpdesk check previously used
`_collect_manifest_evidence_ids` (EVID-regex only), so `HD-*` ticket ids injected
into manifest claims were invisible. Added `_collect_manifest_positive_claim_ids`
for helpdesk validation.

### Determinism

`test_build_is_deterministic_via_manifest`: two builds with same seed → identical
`MANIFEST.json` file map and `dataset_sha256`.

### Manual DP2 truth-projector check (DONE 2026-07-12)

Procedure (colonial `canonical_events.ndjson`, seed=42, window 08:00Z):

1. Load baseline canonical NDJSON
2. Strip `phase='unknown'`, `attack=[]`, `actor='unknown'` on every row (same as
   `scripts/strip_dp2.py`)
3. Rebuild all five truth manifests from stripped file via `build_*_manifest_from_file`
4. Compare SHA-256 of canonical JSON-serialized manifests (sorted keys)

Result: **all five projectors identical** baseline vs stripped.

| Task | SHA-256 (baseline == stripped) |
|------|--------------------------------|
| fox | `1b8074a0148a5f8b1936878e163f652fd4b45cf95b0074ac8cf6fed4fb2d9562` |
| goat | `1406cd9853df1e60e31ca1435176fd30e89d09c50cd8e8db127f4bacf0ab7863` |
| mouse | `29ecd2bce8f65793a4cddc1d6093d193464ff92d73d320985d1b1a539bae5250` |
| tiger | `8b27245ed6aac17f9db730251e2967b4d9f5343ff0664e8c32cb03deef6be82c` |
| panda | `da265e3ff711cdaeca2f0b28fbe4f1c4bde90ed379006a5f9a6bc1b26ff2cb5a` |

Conclusion: truth projectors do **not** depend on grader-only `phase`/`attack`/`actor`
labels for colonial ground truth (consistent with per-projector unit tests
`test_*_ignores_ground_truth_labels`).

## Test results

```
pytest tests/socbench/ --no-cov  → 122 passed
```

## Fork purity

No changes under `src/evidenceforge/`.
