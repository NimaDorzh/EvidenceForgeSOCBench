# Worklog: Step 5 — WorldState + Stage Bucketize (2026-07-12)

## Goal

Implement `src/socbench/stage/` for cumulative 30-minute agent staging with
late-source gating, static `WorldState` seam for future interactive Panda, and
CLI `--stream-by-stage`.

## Implemented

```
src/socbench/stage/
  world_state.py   # StaticWorldState + Intervention + WorldState Protocol
  bucketize.py     # agent/stage_XX/ slicing + helpdesk min_stage_gate
tests/socbench/test_stage.py
docs/design/interactive-world-state.md
```

CLI:

```powershell
# Bucketize only
socbench stage bucketize -b <bundle> --window-start 2024-06-03T08:00:00Z --stream-by-stage

# Build sources then bucketize
socbench sources build -e <canonical_events.ndjson> -b <bundle> --seed 42 `
  --window-start 2024-06-03T08:00:00Z --stream-by-stage
```

### Bucketize contract

| Input | Output |
|-------|--------|
| `<bundle>/data/{siem,hostmetrics,vss,helpdesk,cti,process_telemetry}/**/*.ndjson` | `agent/stage_XX/data/...` cumulative through stage XX |
| `<bundle>/grader/canonical_events.ndjson` | `agent/stage_XX/canonical_events.ndjson` cumulative slice |

Each exported record carries explicit `stage_index` (floor(Δt / stage_minutes)).

**Helpdesk gating:** reads precomputed `min_stage_gate` from ticket payload (step 4).
Does **not** recompute from `latency_applied_ms`. Ticket omitted when
`agent_stage < min_stage_gate`.

**CTI gating:** no `min_stage_gate` field on user-linked rows; time-based via `ts`
only (latency already applied at build time).

### Static WorldState

- `apply()` — no-op; appends intervention to tuple for interface tests.
- `replan_tail(from_stage)` — returns unchanged tail events with
  `stage_index >= from_stage` (no EF re-run).

### Tests (colonial, seed=42, window 08:00Z)

- `test_world_state_interface_signatures` — typed apply/replan seam only
- `test_helpdesk_empty_before_min_stage_gate` — stages `< max_stage // 2` have no tickets (colonial; gate aligns with late ts)
- `test_helpdesk_min_stage_gate_suppresses_early_timestamp` — ticket `ts` in stage 1, `min_stage_gate=4`; absent in stages 0–3, present from stage 4 (proves gate is enforced, not redundant with ts)
- `test_cti_user_linked_rows_gate_by_timestamp_only` — no `min_stage_gate` on CTI rows
- `test_no_linked_evidence_leaks_into_earlier_agent_stages` — storyline-level leak check
- `test_bucketize_is_deterministic_by_sha256` — identical agent tree across runs
- `test_panda_regression_after_world_state_refactor` — Panda via `StaticWorldState`

### Fork purity

No changes under `src/evidenceforge/`.

## Next (Step 6)

- `export_dataset.py` + DP2 strip of `__grader_metadata` from agent exports
- `validate.py` consistency checks using `stage_index` + linked evidence stages
