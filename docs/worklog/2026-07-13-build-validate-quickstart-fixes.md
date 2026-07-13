# SOC-bench build/validate quick-start fixes (2026-07-13)

## Bug 1 — `SameFileError` on first-ever `socbench build`

### Symptom

`python -m socbench build` against a freshly generated scenario bundle (no prior
`socbench capture`, no `grader/canonical_events.ndjson`) crashed with
`SameFileError` when `stream_by_stage=True`.

### Root cause

`_resolve_canonical_events()` wrote freshly built canonical events directly to
`staging/grader/canonical_events.ndjson`, then `build_dataset()` unconditionally
`shutil.copy2()`'d that same path into `staging/grader/` again.

Pre-existing bundles took the early-return branch (`bundle_dir/grader/...`) so the
copy source and destination differed; committed fixtures always had
`grader/canonical_events.ndjson`, so the fresh-build branch was never hit in CI.

### Fix

Skip the staging copy when `events_path.resolve()` already equals the staging
destination (`export_dataset.py`).

### Verification

- `tests/socbench/test_export_dataset.py::test_build_dataset_without_preexisting_grader_canonical_events`
- Manual: delete `grader/` from a bundle copy, `build_dataset(stream_by_stage=True)` succeeds

---

## Bug 2 — Panda future-stage evidence leak on branch-office

### Symptom

`python -m socbench validate` failed on branch-office builds using the README /
email quick-start `--window-start 2024-06-03T08:00:00Z` (Colonial timeline):

```
panda.json stage 0: claim references future evidence EVID-7f8d5ad1 (event stage 1)
```

Colonial builds passed because event timestamps align with that origin.

### Root cause

Two interacting issues:

1. **Misaligned explicit window-start.** Branch-office events occur on
   `2024-05-14`, but the quick-start passes Colonial's `2024-06-03T08:00:00Z`.
   `stage_of()` clamps pre-origin events to stage 0, collapsing a ~49-minute
   incident into a single stage. Panda stage 0 then classified the full timeline
   as `staging` and cited `EVID-7f8d5ad1` (Compress-Archive) in stage 0.

2. **Validate/build origin mismatch.** Manifests were built with the explicit
   June origin, but `validate_causality_respects_stage_order()` inferred origin
   from the earliest May event. Under the inferred origin, `EVID-7f8d5ad1` is
   stage 1 while Panda stage 0 still cited it.

This is the same non-Colonial timing-assumption class as prior `siem.py` /
`helpdesk.py` hardening — logic that holds on Colonial silently breaks when
event timestamps do not match the supplied `--window-start`.

### Fix

| Layer | Change |
|-------|--------|
| `truth/common.py` | `coerce_window_start_for_staging()` — when explicit origin postdates all events and would collapse multi-bucket timelines, fall back to inferred earliest-event origin with a warning |
| `export_dataset.py` | Apply coercion before manifest/source staging |
| `validate.py` | `_manifest_window_start()` — causality checks use `window_start` recorded in fox/goat/panda manifests |
| `truth/panda.py` | `_supporting_evidence_ids()` filters by `stage_of(event) <= current_stage` |

Tradeoff: coercion rewrites an explicitly supplied but misaligned `--window-start`
rather than producing a single-stage dataset that passes only after weakening
validation. Manifests record the coerced origin so validate and grader agree.

### Verification

| Check | Result |
|-------|--------|
| `test_export_dataset.py::test_branch_office_build_with_colonial_style_window_start_validates` | ✅ |
| `test_panda_truth.py::test_panda_stage_boundary_supporting_evidence_stays_in_stage` | ✅ |
| Colonial `build` + `validate` | ✅ |
| `pytest tests/socbench -m "not slow"` | ✅ (run in fresh venv) |

Chainsaw / EVTX: out of scope for this entry (separate worklog).
