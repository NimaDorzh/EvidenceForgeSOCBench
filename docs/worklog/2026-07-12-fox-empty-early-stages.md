# Fox empty early stages — window-start vs canonical events (2026-07-12)

## Found

`build_fox_manifest` crashed with an unhandled `ValueError`:

```
File "src/socbench/truth/fox.py", line 59, in build_fox_manifest
    first_event = min(cumulative, key=lambda event: parse_ts(event.ts))
ValueError: min() iterable argument is empty
```

## Reproduction

```bash
python -m socbench capture -b output/retail-test \
  -s tests/fixtures/scenarios/retail-store-ftp-attack.yaml --seed 42

python -m socbench truth build \
  --events output/retail-test/grader/canonical_events.ndjson \
  --out output/retail-test/grader \
  --window-start 2024-01-15T05:00:00Z
```

Retail scenario declares `time_window.start: 2024-01-15T05:00:00Z`, but the
first canonical attack event is ~10.5 hours later (`2024-01-15T15:29:39Z`).
With default 30-minute stages, stages 0..20 have an empty cumulative slice.

With `--window-start 2024-01-15T15:00:00Z` the build succeeds.

## Root cause

Fox assumed every stage's cumulative slice was non-empty and called `min()` to
seed `first_affected_host` without guarding empty lists. Goat/Panda/Mouse/Tiger
did not hit the same failure mode (Goat never calls `min()` on cumulative;
Mouse guards exfil list; Tiger/Panda unaffected).

## Fix

- `fox.py`: only update `first_affected_*` / ransomware markers when
  `cumulative` is non-empty (final stage always includes all events when
  `max_stage` is derived from the event list).
- `common.py`: `resolve_window_start()` + `window_start_alignment_warning()`
  for shared staging origin resolution and CLI diagnostics.
- `__main__.py`: print a yellow warning when `--window-start` precedes the
  earliest canonical event by one or more full stages.

## Verification

```bash
python -m pytest tests/socbench/test_fox_truth.py::test_fox_skips_empty_early_stages -v --no-cov
python -m pytest tests/socbench -v --no-cov
```

Retail regression (after capture):

```bash
python -m socbench truth build \
  --events output/retail-test/grader/canonical_events.ndjson \
  --out output/retail-test/grader \
  --window-start 2024-01-15T05:00:00Z
```

Expected: warning about empty early stages, manifest written, no traceback.
