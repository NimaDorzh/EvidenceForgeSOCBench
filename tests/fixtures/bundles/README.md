# Non-Colonial SOC-bench regression bundles

Minimal committed fixtures for `tests/socbench/test_non_colonial_build.py`.
Each bundle contains only what `socbench build` needs:

- `scenario.yaml` — environment topology for grader manifests and agent topology
- `grader/canonical_events.ndjson` — captured attack timeline (seed=42)

These are **required** core regression inputs. Tests call `pytest.fail` (not
`pytest.skip`) when files are missing so CI cannot go green without running the
checks.

To refresh after intentional canonical-event changes:

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
