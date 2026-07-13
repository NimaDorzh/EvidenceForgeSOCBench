"""Shared paths and markers for Colonial Pipeline test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Committed minimal bundle (~76 KB): scenario, capture metadata, canonical events.
COLONIAL_FIXTURE_BUNDLE = REPO_ROOT / "tests" / "fixtures" / "bundles" / "colonial"
COLONIAL_SCENARIO = COLONIAL_FIXTURE_BUNDLE / "scenario.yaml"
COLONIAL_EVENTS = COLONIAL_FIXTURE_BUNDLE / "grader" / "canonical_events.ndjson"
COLONIAL_WINDOW_START = "2024-06-03T08:00:00Z"

# Optional local EF output with full data/ (~73 MB, gitignored under scenarios/*).
COLONIAL_FULL_BUNDLE = REPO_ROOT / "scenarios" / "colonial-pipeline"
COLONIAL_FULL_DATA_DIR = COLONIAL_FULL_BUNDLE / "data"

_COLONIAL_FULL_DATA_SKIP_REASON = (
    "Requires full colonial-pipeline data/ (~73MB, not in git). "
    "Generate locally: `uv run eforge generate --scenario scenarios/colonial-pipeline/scenario.yaml "
    "--seed 42 --force`. See tests/fixtures/bundles/README.md."
)

REQUIRES_COLONIAL_FULL_DATA = pytest.mark.skipif(
    not COLONIAL_FULL_DATA_DIR.is_dir(),
    reason=_COLONIAL_FULL_DATA_SKIP_REASON,
)

# Backward-compatible aliases used across tests/socbench/.
COLONIAL_BUNDLE = COLONIAL_FULL_BUNDLE
COLONIAL_DATA = COLONIAL_FULL_DATA_DIR


def require_committed_colonial_fixture() -> None:
    """Fail fast when the committed colonial fixture bundle is missing from checkout."""
    missing: list[str] = []
    for path in (
        COLONIAL_SCENARIO,
        COLONIAL_EVENTS,
        COLONIAL_FIXTURE_BUNDLE / "GROUND_TRUTH.json",
        COLONIAL_FIXTURE_BUNDLE / "OBSERVATION_MANIFEST.json",
    ):
        if not path.is_file():
            missing.append(str(path.relative_to(REPO_ROOT)))
    if missing:
        pytest.fail(
            "committed colonial fixture must be present under tests/fixtures/bundles/colonial/: "
            f"missing {missing}"
        )


def resolve_colonial_capture_bundle() -> Path:
    """Return the local full EF bundle path or skip with an explicit reason."""
    if not COLONIAL_FULL_DATA_DIR.is_dir():
        pytest.skip(_COLONIAL_FULL_DATA_SKIP_REASON)
    return COLONIAL_FULL_BUNDLE
