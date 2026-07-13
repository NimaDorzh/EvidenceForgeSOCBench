# SOC-bench regression bundle fixtures

Committed minimal bundles for `tests/socbench/`. Each bundle contains what
`socbench build` and truth/source tests need without full EF `data/` trees.

## Layout (all bundles)

| Path | Purpose |
|------|---------|
| `scenario.yaml` | Environment topology for grader manifests and agent topology |
| `grader/canonical_events.ndjson` | Captured attack timeline (seed=42) |

## Retail & branch-office (~1 MB total)

Used by `tests/socbench/test_non_colonial_build.py`.

These are **required** core regression inputs. Tests call `pytest.fail` (not
`pytest.skip`) when files are missing so CI cannot go green without running the
checks.

### Refresh retail / branch canonical events

```bash
uv run socbench capture --bundle output/retail-test \
  --scenario tests/fixtures/scenarios/retail-store-ftp-attack.yaml --seed 42
cp output/retail-test/grader/canonical_events.ndjson \
  tests/fixtures/bundles/retail/grader/

uv run socbench capture --bundle output/branch-office-test \
  --scenario scenarios/branch-office-example/scenario.yaml --seed 42
cp output/branch-office-test/grader/canonical_events.ndjson \
  tests/fixtures/bundles/branch-office/grader/
```

## Colonial Pipeline (~76 KB committed)

Path: `tests/fixtures/bundles/colonial/`

| File | In git? | Purpose |
|------|---------|---------|
| `scenario.yaml` | yes | Colonial topology |
| `grader/canonical_events.ndjson` | yes | 21-event timeline for truth/sources/stage/export |
| `GROUND_TRUTH.json` | yes | Capture metadata for `build_canonical_events` contract |
| `OBSERVATION_MANIFEST.json` | yes | Observation profile metadata |
| `data/` (~73 MB EF output) | **no** | Zeek/eCAR/XML/syslog for `output_refs` backfill & binary-format colonial tests |

Most `tests/socbench/` colonial tests read the committed fixture via
`tests.socbench.colonial_fixtures`. Tests that resolve raw log files under
`data/` are marked with `@REQUIRES_COLONIAL_FULL_DATA` and skip with an explicit
reason when local EF output is absent.

### Generate full colonial `data/` locally (optional)

The gitignored tree lives at `scenarios/colonial-pipeline/` (see `.gitignore`
`scenarios/*`). Generate with EvidenceForge, then run capture if refreshing
canonical events:

```bash
uv run eforge generate \
  --scenario scenarios/colonial-pipeline/scenario.yaml \
  --seed 42 --force

uv run socbench capture \
  --bundle scenarios/colonial-pipeline \
  --scenario scenarios/colonial-pipeline/scenario.yaml \
  --seed 42

# Refresh committed canonical + metadata after intentional storyline changes:
cp scenarios/colonial-pipeline/grader/canonical_events.ndjson \
  tests/fixtures/bundles/colonial/grader/
cp scenarios/colonial-pipeline/GROUND_TRUTH.json \
  tests/fixtures/bundles/colonial/
cp scenarios/colonial-pipeline/OBSERVATION_MANIFEST.json \
  tests/fixtures/bundles/colonial/
```

### Future: Git LFS for `data/`

Full colonial `data/` is intentionally out of git (generated EF artifacts, not
source-of-truth). A tracked backlog item covers optional Git LFS hosting so CI
can run `@REQUIRES_COLONIAL_FULL_DATA` tests without a local `eforge generate`.
See `TODO.md` → SOC-bench colonial full-data fixtures.
