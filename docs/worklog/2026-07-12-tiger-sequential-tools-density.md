# Tiger sequential_tools_same_host combinatorial growth (2026-07-12)

## Found

On retail-test (22 canonical events, single host `MUSIC-SRV-01`), Tiger emitted
**173 contextual edges**, nearly all from `sequential_tools_same_host`. With 22
process-eligible events on one host, the pre-fix rule linked most within-window
process pairs (approaching C(22,2)=231).

Colonial Pipeline (multi-host, 21 events, pre-fix): contextual=8, verifiable=6
— healthy ratio.

## Reproduction

```bash
python -m socbench capture -b output/retail-test \
  -s tests/fixtures/scenarios/retail-store-ftp-attack.yaml --seed 42

python -m socbench truth build \
  --events output/retail-test/grader/canonical_events.ndjson \
  --out output/retail-test/grader \
  --window-start 2024-01-15T15:00:00Z
```

Inspect `tiger.json` summary and edge rules.

## Root cause

`_build_contextual_edges` iterated all ordered process pairs on the same host
within a 30-minute window — O(n²) per host with no cap on out-degree. On
single-host RCE scenarios without lateral movement, this produced a near-complete
directed graph, weakening GED discrimination despite higher verifiable weights.

`source_attribution` was already populated via `_merge_attribution()` when
`observed_by` is present on canonical events; empty `[]` on retail reflected
missing observation metadata on some rows, not a missing code path.

## Fix

`sequential_tools_same_host` now uses a **per-host temporal chain**:

| Parameter | Value |
|---|---|
| `SEQUENTIAL_CONTEXT_WINDOW_MINUTES` | 15 |
| `SEQUENTIAL_CONTEXT_MAX_SUCCESSORS` | 3 |

Each process links only to the next ≤3 temporal successors on the same host
within the window — O(n) edge growth instead of O(n²).

Manifest `assumptions.sequential_tools_same_host` documents the limits.

## Verification

```bash
python -m pytest tests/socbench/test_tiger_truth.py::test_sequential_tools_same_host_growth_is_bounded -v --no-cov
python -m pytest tests/socbench/test_tiger_truth.py::test_colonial_tiger_has_non_empty_verifiable_core -v --no-cov
python -m pytest tests/socbench -v --no-cov
```

Retail regression: contextual count for `sequential_tools_same_host` should be
≪ 173 and scale linearly with process count on one host.

## Colonial regression (discovered post-fix, independent verification)

Re-running truth build on Colonial Pipeline after this fix changed the
contextual edge count:

| | verifiable | contextual |
|---|---|---|
| Pre-fix | 6 | 8 |
| Post-fix | 6 | 4 |

This was not caught by `test_colonial_tiger_has_non_empty_verifiable_core`,
which only asserts `verifiable > 0` and does not pin the contextual count.
The 4 remaining contextual edges post-fix carry non-empty
`source_attribution` and consist of 3 `sequential_tools_same_host` edges plus
1 `lateral_shared_source_ip` edge — consistent with the tighter 15-minute
window / 3-successor cap filtering out looser same-host pairs that no longer
qualify.

No regression test currently pins the exact Colonial contextual edge set;
if this count needs to stay stable across future changes to
`sequential_tools_same_host`, consider adding an explicit assertion on it.
