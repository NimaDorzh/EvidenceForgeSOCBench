# Interactive WorldState design note (future work)

## Status

v1 ships **static mode only**:

- `StaticWorldState.apply()` records interventions but does not mutate events.
- `StaticWorldState.replan_tail()` returns the unchanged tail slice from
  `from_stage` onward (no EF re-run).

The typed `WorldState` / `Intervention` interface exists so interactive
containment can be added without reshaping Panda truth or the stage bucketizer.

## Planned interactive flow

1. Agent issues `Intervention` after stage `N` (for example `isolate_host`).
2. `WorldState.apply()` patches scenario state (segment, account, egress policy).
3. `replan_tail(from_stage=N+1)` triggers a **deterministic EF re-run** with the
   patched `scenario.yaml`.
4. Panda (and other stage projectors) recompute manifests from the new tail via
   `WorldState.slice_through`.

## Evidence ID stability problem

A naïve EF re-run regenerates tail canonical events with fresh `evidence_id`
values. That breaks:

- `__grader_metadata.linked_evidence_ids` on synthetic sources built in step 4
- Tiger verifiable edges keyed by `evidence_id`
- Fox/Goat/Panda cumulative stage manifests
- Validate rules that cross-reference agent-stage exports against grader truth

### Candidate policy (not implemented)

- **Prefix pre-intervention ids** with a stable stage boundary marker and never
  rewrite ids for events at or before the intervention stage.
- **Relink tail sources** by `(host, kind, ts, observable fingerprint)` rather
  than raw `evidence_id` equality.
- **Version grader manifests** per intervention sequence so benchmarks can compare
  containment quality without pretending ids are globally stable.

Until a policy is chosen and tested, interactive mode must remain behind an
explicit feature flag and out of the v1 publication path.
