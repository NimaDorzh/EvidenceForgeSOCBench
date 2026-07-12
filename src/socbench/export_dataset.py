"""End-to-end SOC-bench dataset build orchestration."""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.paths import safe_write_text
from socbench.capture.canonical_events import (
    CANONICAL_EVENTS_FILENAME,
    build_canonical_events,
    write_canonical_events,
)
from socbench.export_agent import export_agent_tree
from socbench.integrity.signatures import write_manifest
from socbench.mutate.augment import AugmentConfig, augment_source_tree
from socbench.sources import build_sources_from_file
from socbench.sources.models import SourceBuildConfig
from socbench.stage.bucketize import bucketize_bundle
from socbench.truth.common import load_canonical_events, resolve_window_start
from socbench.truth.fox import (
    FOX_MANIFEST_FILENAME,
    build_fox_manifest_from_file,
    write_fox_manifest,
)
from socbench.truth.goat import (
    GOAT_MANIFEST_FILENAME,
    build_goat_manifest_from_file,
    write_goat_manifest,
)
from socbench.truth.mouse import (
    MOUSE_MANIFEST_FILENAME,
    build_mouse_manifest_from_file,
    write_mouse_manifest,
)
from socbench.truth.panda import (
    PANDA_MANIFEST_FILENAME,
    build_panda_manifest_from_file,
    write_panda_manifest,
)
from socbench.truth.tiger import (
    TIGER_GED_SPEC_FILENAME,
    TIGER_MANIFEST_FILENAME,
    build_tiger_ged_spec,
    build_tiger_manifest_from_file,
    write_tiger_ged_spec,
    write_tiger_manifest,
)

logger = logging.getLogger(__name__)

DEFAULT_TASKS = ("fox", "goat", "mouse", "tiger", "panda")
EVIDENCE_REGISTRY_FILENAME = "evidence_registry.json"
TOPOLOGY_FILENAME = "topology.json"
STAGING_DIRNAME = "_staging"


@dataclass(frozen=True, slots=True)
class DatasetBuildConfig:
    """Configuration for a full SOC-bench dataset build."""

    scenario_path: Path
    output_dir: Path
    seed: int = 42
    tasks: tuple[str, ...] = DEFAULT_TASKS
    window_start: str | None = None
    stage_minutes: int = 30
    stream_by_stage: bool = True
    mutate_seed: int | None = None


@dataclass(frozen=True, slots=True)
class DatasetBuildResult:
    """Summary of a completed dataset build."""

    output_dir: Path
    manifest_path: Path
    stage_count: int
    canonical_event_count: int


def build_dataset(config: DatasetBuildConfig) -> DatasetBuildResult:
    """Build a complete agent/grader dataset tree under ``config.output_dir``."""
    scenario_path = config.scenario_path.resolve()
    output_dir = config.output_dir.resolve()
    bundle_dir = scenario_path.parent
    staging = output_dir / STAGING_DIRNAME

    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    scenario = _load_scenario(scenario_path)
    events_path = _resolve_canonical_events(bundle_dir, scenario, config.seed, staging)
    events = load_canonical_events(events_path)
    window_start = config.window_start
    if window_start is None and events:
        window_start = resolve_window_start(events, None).strftime("%Y-%m-%dT%H:%M:%SZ")

    source_config = SourceBuildConfig(
        seed=config.seed,
        window_start=window_start,
        stage_minutes=config.stage_minutes,
    )
    data_root = staging / "data"
    build_sources_from_file(events_path, data_root, source_config)

    if config.mutate_seed is not None:
        augment_source_tree(
            data_root,
            AugmentConfig(
                seed=config.mutate_seed,
                rename_hosts=True,
                mutate_helpdesk_text=True,
                mutate_cti_indicators=True,
            ),
        )

    stage_count = 1
    if config.stream_by_stage:
        grader_staging = staging / "grader"
        grader_staging.mkdir(parents=True, exist_ok=True)
        shutil.copy2(events_path, grader_staging / CANONICAL_EVENTS_FILENAME)
        bucket_result = bucketize_bundle(
            staging,
            events_path=events_path,
            agent_root=staging / "agent_raw",
            window_start=window_start,
            stage_minutes=config.stage_minutes,
        )
        stage_count = bucket_result.stage_count
        export_agent_tree(staging / "agent_raw", output_dir / "agent")
    else:
        export_agent_tree(data_root, output_dir / "agent" / "data")

    topology_path = output_dir / "agent" / TOPOLOGY_FILENAME
    safe_write_text(
        topology_path,
        json.dumps(build_topology_json(scenario), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    grader_root = output_dir / "grader"
    manifests_dir = grader_root / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(events_path, grader_root / CANONICAL_EVENTS_FILENAME)
    _write_grader_manifests(
        events_path,
        manifests_dir,
        tasks=config.tasks,
        window_start=window_start,
        stage_minutes=config.stage_minutes,
    )
    registry_path = grader_root / EVIDENCE_REGISTRY_FILENAME
    safe_write_text(
        registry_path,
        json.dumps(build_evidence_registry(events), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    manifest_path = write_manifest(output_dir)
    shutil.rmtree(staging)

    return DatasetBuildResult(
        output_dir=output_dir,
        manifest_path=manifest_path,
        stage_count=stage_count,
        canonical_event_count=len(events),
    )


def build_topology_json(scenario: Scenario) -> dict[str, Any]:
    """Extract agent-visible topology from scenario environment metadata."""
    environment = scenario.environment
    systems: list[dict[str, Any]] = []
    for system in environment.systems:
        systems.append(
            {
                "hostname": system.hostname,
                "ip": system.ip,
                "os": system.os,
                "type": system.type,
                "roles": sorted(system.roles or []),
                "services": sorted(system.services or []),
            }
        )

    segments: list[dict[str, Any]] = []
    network = environment.network
    if network is not None:
        for segment in network.segments or []:
            segments.append(
                {
                    "name": segment.name,
                    "cidr": segment.cidr,
                    "description": segment.description,
                    "systems": list(segment.systems or []),
                }
            )

    return {
        "schema_version": 1,
        "scenario": scenario.name,
        "domain": environment.domain,
        "systems": sorted(systems, key=lambda item: str(item["hostname"])),
        "segments": segments,
    }


def build_evidence_registry(events: list[Any]) -> dict[str, Any]:
    """Build grader-facing evidence registry from canonical events."""
    rows = [
        {
            "evidence_id": event.evidence_id,
            "record_id": event.record_id,
            "storyline_id": event.storyline_id,
            "host": event.host,
            "kind": event.kind,
            "ts": event.ts,
            "observation_status": event.observation_status,
        }
        for event in events
    ]
    return {
        "schema_version": 1,
        "count": len(rows),
        "events": sorted(rows, key=lambda item: (item["ts"], item["evidence_id"])),
    }


def _load_scenario(path: Path) -> Scenario:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Scenario.model_validate(data)


def _resolve_canonical_events(
    bundle_dir: Path,
    scenario: Scenario,
    seed: int,
    staging: Path,
) -> Path:
    grader_path = bundle_dir / "grader" / CANONICAL_EVENTS_FILENAME
    if grader_path.is_file():
        return grader_path

    events = build_canonical_events(bundle_dir, scenario, seed=seed)
    out_path = staging / "grader" / CANONICAL_EVENTS_FILENAME
    write_canonical_events(events, out_path)
    return out_path


def _write_grader_manifests(
    events_path: Path,
    manifests_dir: Path,
    *,
    tasks: tuple[str, ...],
    window_start: str | None,
    stage_minutes: int,
) -> None:
    selected = {task.lower() for task in tasks}
    if "fox" in selected:
        write_fox_manifest(
            build_fox_manifest_from_file(
                events_path,
                window_start=window_start,
                stage_minutes=stage_minutes,
            ),
            manifests_dir / FOX_MANIFEST_FILENAME,
        )
    if "goat" in selected:
        write_goat_manifest(
            build_goat_manifest_from_file(
                events_path,
                window_start=window_start,
                stage_minutes=stage_minutes,
            ),
            manifests_dir / GOAT_MANIFEST_FILENAME,
        )
    if "mouse" in selected:
        write_mouse_manifest(
            build_mouse_manifest_from_file(events_path),
            manifests_dir / MOUSE_MANIFEST_FILENAME,
        )
    if "tiger" in selected:
        write_tiger_manifest(
            build_tiger_manifest_from_file(events_path),
            manifests_dir / TIGER_MANIFEST_FILENAME,
        )
        write_tiger_ged_spec(build_tiger_ged_spec(), manifests_dir / TIGER_GED_SPEC_FILENAME)
    if "panda" in selected:
        write_panda_manifest(
            build_panda_manifest_from_file(
                events_path,
                window_start=window_start,
                stage_minutes=stage_minutes,
            ),
            manifests_dir / PANDA_MANIFEST_FILENAME,
        )

    unsupported = selected - set(DEFAULT_TASKS)
    if unsupported:
        msg = f"Unsupported truth tasks: {', '.join(sorted(unsupported))}"
        raise ValueError(msg)
