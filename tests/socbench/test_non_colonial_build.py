"""Permanent non-Colonial full-build regression guards."""

from __future__ import annotations

from pathlib import Path

import pytest

from socbench.export_dataset import DatasetBuildConfig, build_dataset
from socbench.validate import validate_agent_stage_count_aligned, validate_dataset

REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "bundles"
COMMITTED_BUNDLE_DIRS = (
    BUNDLE_FIXTURES / "retail",
    BUNDLE_FIXTURES / "branch-office",
)

NON_COLONIAL_BUILD_CASES = (
    pytest.param(
        BUNDLE_FIXTURES / "retail",
        "2024-01-15T15:00:00Z",
        id="retail",
    ),
    pytest.param(
        BUNDLE_FIXTURES / "branch-office",
        "2024-05-14T12:00:00Z",
        id="branch-office",
    ),
)


def _require_committed_bundle(bundle_dir: Path) -> None:
    """Fail fast when core regression fixtures are missing from the repo checkout."""
    scenario_path = bundle_dir / "scenario.yaml"
    canonical_path = bundle_dir / "grader" / "canonical_events.ndjson"
    missing: list[str] = []
    if not scenario_path.is_file():
        missing.append(str(scenario_path.relative_to(REPO_ROOT)))
    if not canonical_path.is_file():
        missing.append(str(canonical_path.relative_to(REPO_ROOT)))
    if missing:
        pytest.fail(
            "non-Colonial regression fixtures must be committed under "
            f"tests/fixtures/bundles/: missing {missing}"
        )


def test_non_colonial_regression_fixtures_are_committed() -> None:
    """Guard against silent CI skip when bundle fixtures are missing from checkout."""
    for bundle_dir in COMMITTED_BUNDLE_DIRS:
        _require_committed_bundle(bundle_dir)


@pytest.mark.parametrize(("bundle_dir", "window_start"), NON_COLONIAL_BUILD_CASES)
def test_non_colonial_full_build_stage_count_aligned(
    bundle_dir: Path,
    window_start: str,
    tmp_path: Path,
) -> None:
    """Regression guard: non-Colonial full builds stay stage-bounded after source changes."""
    _require_committed_bundle(bundle_dir)
    out_dir = tmp_path / f"dataset-{bundle_dir.name}"

    build_dataset(
        DatasetBuildConfig(
            scenario_path=(bundle_dir / "scenario.yaml").resolve(),
            output_dir=out_dir,
            seed=42,
            window_start=window_start,
            stream_by_stage=True,
        )
    )

    stage_errors = validate_agent_stage_count_aligned(out_dir)
    assert stage_errors == [], stage_errors

    result = validate_dataset(out_dir)
    assert result.ok, result.errors
