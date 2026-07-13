"""Tests for SOC-bench data augmentation invariants."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from socbench.mutate.augment import AugmentConfig, augment_source_tree
from socbench.sources import build_sources_from_file
from socbench.sources.models import SourceBuildConfig
from socbench.truth.fox import build_fox_manifest_from_file
from socbench.truth.goat import build_goat_manifest_from_file
from socbench.truth.mouse import build_mouse_manifest_from_file
from socbench.truth.panda import build_panda_manifest_from_file
from socbench.truth.tiger import build_tiger_manifest_from_file
from tests.socbench.colonial_fixtures import COLONIAL_EVENTS, COLONIAL_WINDOW_START

TRUTH_PROJECTORS = ("fox", "goat", "mouse", "tiger", "panda")


def _truth_manifests_by_projector(events_path: Path) -> dict[str, dict[str, object]]:
    """Build full truth manifests for all five projectors (pre/post augment comparison)."""
    return {
        "fox": build_fox_manifest_from_file(events_path, window_start=COLONIAL_WINDOW_START),
        "goat": build_goat_manifest_from_file(events_path, window_start=COLONIAL_WINDOW_START),
        "mouse": build_mouse_manifest_from_file(events_path),
        "tiger": build_tiger_manifest_from_file(events_path),
        "panda": build_panda_manifest_from_file(events_path, window_start=COLONIAL_WINDOW_START),
    }


def _linked_evidence_ids_by_record(source_root: Path) -> dict[str, list[str]]:
    """Map record key -> sorted linked_evidence_ids from __grader_metadata."""
    mapping: dict[str, list[str]] = {}
    for path in source_root.rglob("*.ndjson"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            metadata = row.get("__grader_metadata")
            if not isinstance(metadata, dict):
                continue
            record_id = str(
                row.get("record_id", row.get("ticket_id", row.get("alert_id", path.name)))
            )
            linked = metadata.get("linked_evidence_ids", [])
            mapping[record_id] = sorted(str(item) for item in linked)
    return mapping


def _helpdesk_texts(source_root: Path) -> list[str]:
    path = source_root / "helpdesk" / "tickets.ndjson"
    if not path.is_file():
        return []
    return [
        str(json.loads(line)["text"])
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.mark.skipif(
    not COLONIAL_EVENTS.is_file(),
    reason="committed colonial fixture missing: tests/fixtures/bundles/colonial/",
)
def test_augment_invariant_preserves_truth_projectors_and_linked_evidence_ids(
    tmp_path: Path,
) -> None:
    """Augment must leave truth manifests and __grader_metadata.linked_evidence_ids unchanged."""
    data_root = tmp_path / "data"
    build_sources_from_file(
        COLONIAL_EVENTS,
        data_root,
        SourceBuildConfig(seed=42, window_start=COLONIAL_WINDOW_START),
    )

    before_manifests = _truth_manifests_by_projector(COLONIAL_EVENTS)
    before_linked = _linked_evidence_ids_by_record(data_root)
    before_helpdesk = _helpdesk_texts(data_root)
    assert before_linked, "expected attack-linked source records before augment"

    augment_source_tree(
        data_root,
        AugmentConfig(
            seed=99, rename_hosts=True, mutate_helpdesk_text=True, mutate_cti_indicators=True
        ),
    )

    after_manifests = _truth_manifests_by_projector(COLONIAL_EVENTS)
    after_linked = _linked_evidence_ids_by_record(data_root)
    after_helpdesk = _helpdesk_texts(data_root)

    for projector in TRUTH_PROJECTORS:
        assert before_manifests[projector] == after_manifests[projector], (
            f"{projector} truth manifest changed after augment"
        )
    assert before_linked == after_linked, "linked_evidence_ids changed after augment"
    assert before_helpdesk != after_helpdesk, "expected helpdesk surface text to change"


@pytest.mark.skipif(
    not COLONIAL_EVENTS.is_file(),
    reason="committed colonial fixture missing: tests/fixtures/bundles/colonial/",
)
def test_augment_preserves_grader_linked_evidence_ids(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    build_sources_from_file(
        COLONIAL_EVENTS,
        data_root,
        SourceBuildConfig(seed=42, window_start=COLONIAL_WINDOW_START),
    )

    before = _linked_evidence_ids_by_record(data_root)
    augment_source_tree(data_root, AugmentConfig(seed=77))
    after = _linked_evidence_ids_by_record(data_root)
    assert before == after
