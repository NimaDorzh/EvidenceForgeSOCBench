"""Regression tests for dataset export orchestration."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from socbench.capture.canonical_events import CANONICAL_EVENTS_FILENAME
from socbench.export_dataset import DatasetBuildConfig, build_dataset
from socbench.validate import validate_dataset

REPO_ROOT = Path(__file__).resolve().parents[2]
BRANCH_OFFICE_BUNDLE = REPO_ROOT / "tests" / "fixtures" / "bundles" / "branch-office"
COLONIAL_FIXTURE_BUNDLE = REPO_ROOT / "tests" / "fixtures" / "bundles" / "colonial"
COLONIAL_WINDOW_START = "2024-06-03T08:00:00Z"


def test_build_dataset_without_preexisting_grader_canonical_events(tmp_path: Path) -> None:
    """Fresh bundles must build without SameFileError when canonical events are created inline."""
    bundle_dir = tmp_path / "bundle"
    shutil.copytree(COLONIAL_FIXTURE_BUNDLE, bundle_dir)
    grader_dir = bundle_dir / "grader"
    if grader_dir.is_dir():
        shutil.rmtree(grader_dir)

    out_dir = tmp_path / "dataset"
    result = build_dataset(
        DatasetBuildConfig(
            scenario_path=bundle_dir / "scenario.yaml",
            output_dir=out_dir,
            seed=42,
            window_start=COLONIAL_WINDOW_START,
            stream_by_stage=True,
        )
    )

    assert result.canonical_event_count > 0
    assert (out_dir / "grader" / CANONICAL_EVENTS_FILENAME).is_file()
    assert not (out_dir / "_staging").exists()


@pytest.mark.parametrize("window_start", ["2024-06-03T08:00:00Z", COLONIAL_WINDOW_START])
def test_branch_office_build_with_colonial_style_window_start_validates(
    tmp_path: Path,
    window_start: str,
) -> None:
    """README-style Colonial window-start must not break branch-office causality validation."""
    out_dir = tmp_path / f"dataset-{window_start.replace(':', '')}"
    build_dataset(
        DatasetBuildConfig(
            scenario_path=BRANCH_OFFICE_BUNDLE / "scenario.yaml",
            output_dir=out_dir,
            seed=42,
            tasks=("fox", "goat", "mouse", "tiger", "panda"),
            window_start=window_start,
            stream_by_stage=True,
        )
    )

    result = validate_dataset(out_dir)
    assert result.ok, result.errors
