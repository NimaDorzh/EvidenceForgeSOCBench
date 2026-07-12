"""SOC-bench CLI entrypoint."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console

from evidenceforge.models.scenario import Scenario
from socbench.capture.canonical_events import (
    CANONICAL_EVENTS_FILENAME,
    CaptureMechanism,
    build_canonical_events,
    write_canonical_events,
)
from socbench.export_dataset import DatasetBuildConfig, build_dataset
from socbench.sources import build_sources_from_file
from socbench.sources.common import SOURCE_NAMES, file_digest
from socbench.sources.models import SourceBuildConfig
from socbench.stage.bucketize import bucketize_bundle
from socbench.truth.common import (
    load_canonical_events,
    resolve_window_start,
    window_start_alignment_warning,
)
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
from socbench.validate import validate_dataset

app = typer.Typer(no_args_is_help=True, add_completion=False)
truth_app = typer.Typer(no_args_is_help=True, add_completion=False)
sources_app = typer.Typer(no_args_is_help=True, add_completion=False)
stage_app = typer.Typer(no_args_is_help=True, add_completion=False)
app.add_typer(truth_app, name="truth")
app.add_typer(sources_app, name="sources")
app.add_typer(stage_app, name="stage")
console = Console()
logger = logging.getLogger(__name__)

DEFAULT_TRUTH_TASKS = ("fox", "goat", "mouse", "tiger", "panda")


@app.callback()
def cli() -> None:
    """SOC-bench extensions for EvidenceForge."""


@app.command("build")
def build_command(
    scenario: Annotated[
        Path,
        typer.Option("--scenario", "-s", help="Scenario YAML path"),
    ],
    output: Annotated[
        Path,
        typer.Option("--out", "-o", help="Output dataset directory"),
    ],
    seed: Annotated[
        int,
        typer.Option("--seed", help="Deterministic seed for source generation"),
    ] = 42,
    task: Annotated[
        list[str] | None,
        typer.Option(
            "--tasks",
            "-t",
            help="Truth tasks to build (fox, goat, mouse, tiger, panda)",
        ),
    ] = None,
    window_start: Annotated[
        str | None,
        typer.Option("--window-start", help="Timeline origin ISO timestamp"),
    ] = None,
    stage_minutes: Annotated[
        int,
        typer.Option("--stage-minutes", help="Stage bucket width in minutes"),
    ] = 30,
    stream_by_stage: Annotated[
        bool,
        typer.Option("--stream-by-stage", help="Export cumulative agent stage directories"),
    ] = True,
    mutate_seed: Annotated[
        int | None,
        typer.Option("--mutate-seed", help="Optional augment seed for surface-form mutation"),
    ] = None,
) -> None:
    """Build a full SOC-bench dataset with DP2-gated agent exports."""
    logging.basicConfig(level=logging.INFO)
    selected_tasks = _parse_task_list(task)
    result = build_dataset(
        DatasetBuildConfig(
            scenario_path=scenario.resolve(),
            output_dir=output.resolve(),
            seed=seed,
            tasks=selected_tasks,
            window_start=window_start,
            stage_minutes=stage_minutes,
            stream_by_stage=stream_by_stage,
            mutate_seed=mutate_seed,
        )
    )
    console.print(
        f"[green]Built dataset[/green] ({result.canonical_event_count} events, "
        f"{result.stage_count} stages) -> {result.output_dir}"
    )
    console.print(f"MANIFEST: {result.manifest_path}")


@app.command("validate")
def validate_command(
    dataset: Annotated[
        Path,
        typer.Argument(help="Dataset directory to validate"),
    ],
) -> None:
    """Validate dataset consistency (claims, DP2 gate, causality, Tiger edges)."""
    logging.basicConfig(level=logging.INFO)
    result = validate_dataset(dataset.resolve())
    if result.ok:
        console.print(f"[green]Dataset validation passed[/green] -> {result.dataset_root}")
        return
    console.print(f"[red]Dataset validation failed[/red] -> {result.dataset_root}")
    for error in result.errors:
        console.print(f"  - {error}")
    raise typer.Exit(code=2)


@app.command("capture")
def capture_command(
    bundle: Annotated[
        Path,
        typer.Option("--bundle", "-b", help="Generated EvidenceForge bundle directory"),
    ],
    scenario: Annotated[
        Path,
        typer.Option("--scenario", "-s", help="Scenario YAML used for generation"),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Output NDJSON path (default: <bundle>/grader/canonical_events.ndjson)",
        ),
    ] = None,
    seed: Annotated[
        int | None,
        typer.Option("--seed", help="Deterministic seed for evidence_id assignment"),
    ] = None,
) -> None:
    """Capture canonical events from a generated bundle without modifying EF core."""
    logging.basicConfig(level=logging.INFO)
    bundle_dir = bundle.resolve()
    scenario_path = scenario.resolve()
    scenario_model = _load_scenario(scenario_path)
    events = build_canonical_events(
        bundle_dir,
        scenario_model,
        seed=seed,
        mechanism=CaptureMechanism.POST_GENERATION,
    )
    out_path = (output or (bundle_dir / "grader" / CANONICAL_EVENTS_FILENAME)).resolve()
    write_canonical_events(events, out_path)
    digest = hashlib.sha256(out_path.read_bytes()).hexdigest()
    console.print(f"[green]Wrote {len(events)} canonical events[/green] -> {out_path}")
    console.print(f"SHA-256: {digest}")


@truth_app.command("build")
def truth_build_command(
    events: Annotated[
        Path,
        typer.Option("--events", "-e", help="Path to canonical_events.ndjson"),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--out",
            "-o",
            help="Output directory for truth manifests (default: parent of events file)",
        ),
    ] = None,
    task: Annotated[
        list[str] | None,
        typer.Option(
            "--task",
            "-t",
            help="Truth tasks to build (fox, goat, mouse, tiger, panda)",
        ),
    ] = None,
    window_start: Annotated[
        str | None,
        typer.Option(
            "--window-start",
            help="Timeline origin ISO timestamp (default: earliest canonical event ts)",
        ),
    ] = None,
    stage_minutes: Annotated[
        int,
        typer.Option("--stage-minutes", help="Stage bucket width in minutes"),
    ] = 30,
) -> None:
    """Build grader truth manifests from canonical events."""
    logging.basicConfig(level=logging.INFO)
    events_path = events.resolve()
    out_dir = (output or events_path.parent).resolve()
    selected = set(_parse_task_list(task))

    staged_tasks = selected & {"fox", "goat", "panda"}
    if window_start is not None and staged_tasks:
        canonical_events = load_canonical_events(events_path)
        origin = resolve_window_start(canonical_events, window_start)
        alignment_warning = window_start_alignment_warning(
            canonical_events,
            origin,
            stage_minutes=stage_minutes,
        )
        if alignment_warning:
            console.print(f"[yellow]Warning:[/yellow] {alignment_warning}")

    if "fox" in selected:
        manifest = build_fox_manifest_from_file(
            events_path,
            window_start=window_start,
            stage_minutes=stage_minutes,
        )
        fox_path = write_fox_manifest(manifest, out_dir / FOX_MANIFEST_FILENAME)
        console.print(
            f"[green]Wrote Fox manifest[/green] ({len(manifest.get('stages', []))} stages) -> {fox_path}"
        )

    if "mouse" in selected:
        mouse_manifest = build_mouse_manifest_from_file(events_path)
        mouse_path = write_mouse_manifest(mouse_manifest, out_dir / MOUSE_MANIFEST_FILENAME)
        console.print(
            "[green]Wrote Mouse manifest[/green] "
            f"(exfil={mouse_manifest.get('exfil_happens')}) -> {mouse_path}"
        )

    if "goat" in selected:
        goat_manifest = build_goat_manifest_from_file(
            events_path,
            window_start=window_start,
            stage_minutes=stage_minutes,
        )
        goat_path = write_goat_manifest(goat_manifest, out_dir / GOAT_MANIFEST_FILENAME)
        console.print(
            f"[green]Wrote Goat manifest[/green] "
            f"({len(goat_manifest.get('stages', []))} stages) -> {goat_path}"
        )

    if "tiger" in selected:
        tiger_manifest = build_tiger_manifest_from_file(events_path)
        tiger_path = write_tiger_manifest(tiger_manifest, out_dir / TIGER_MANIFEST_FILENAME)
        ged_spec = build_tiger_ged_spec()
        ged_path = write_tiger_ged_spec(ged_spec, out_dir / TIGER_GED_SPEC_FILENAME)
        summary = tiger_manifest.get("summary", {})
        console.print(
            "[green]Wrote Tiger manifest[/green] "
            f"(verifiable={summary.get('verifiable_edge_count', 0)}, "
            f"contextual={summary.get('contextual_edge_count', 0)}) -> {tiger_path}"
        )
        console.print(f"[green]Wrote Tiger GED spec[/green] -> {ged_path}")

    if "panda" in selected:
        panda_manifest = build_panda_manifest_from_file(
            events_path,
            window_start=window_start,
            stage_minutes=stage_minutes,
        )
        panda_path = write_panda_manifest(panda_manifest, out_dir / PANDA_MANIFEST_FILENAME)
        console.print(
            f"[green]Wrote Panda manifest[/green] "
            f"({len(panda_manifest.get('stages', []))} stages) -> {panda_path}"
        )

    unsupported = selected - {"fox", "mouse", "goat", "tiger", "panda"}
    if unsupported:
        msg = f"Unsupported truth tasks: {', '.join(sorted(unsupported))}"
        raise typer.BadParameter(msg)


@sources_app.command("build")
def sources_build_command(
    events: Annotated[
        Path,
        typer.Option("--events", "-e", help="Path to canonical_events.ndjson"),
    ],
    bundle: Annotated[
        Path,
        typer.Option("--bundle", "-b", help="Bundle directory (writes under bundle/data/)"),
    ],
    seed: Annotated[
        int,
        typer.Option("--seed", help="Deterministic seed for source generation"),
    ] = 42,
    source: Annotated[
        list[str] | None,
        typer.Option("--source", "-s", help="Sources to build (default: all five)"),
    ] = None,
    window_start: Annotated[
        str | None,
        typer.Option("--window-start", help="Timeline origin for stage-gated sources"),
    ] = None,
    stage_minutes: Annotated[
        int,
        typer.Option("--stage-minutes", help="Stage bucket width in minutes"),
    ] = 30,
    helpdesk_min_stage: Annotated[
        int | None,
        typer.Option("--helpdesk-min-stage", help="Minimum stage for helpdesk tickets"),
    ] = None,
    stream_by_stage: Annotated[
        bool,
        typer.Option(
            "--stream-by-stage",
            help="After building sources, slice data/ into agent/stage_XX/ directories",
        ),
    ] = False,
) -> None:
    """Build synthetic SOC-bench sources with hidden grader metadata."""
    logging.basicConfig(level=logging.INFO)
    events_path = events.resolve()
    data_root = (bundle.resolve() / "data").resolve()
    selected = tuple(item.lower() for item in (source or list(SOURCE_NAMES)))
    unsupported = set(selected) - set(SOURCE_NAMES)
    if unsupported:
        msg = f"Unsupported sources: {', '.join(sorted(unsupported))}"
        raise typer.BadParameter(msg)

    config = SourceBuildConfig(
        seed=seed,
        window_start=window_start,
        stage_minutes=stage_minutes,
        helpdesk_min_stage=helpdesk_min_stage,
    )
    results = build_sources_from_file(events_path, data_root, config, selected=selected)
    for result in results:
        console.print(
            f"[green]Built {result.source_name}[/green] "
            f"({result.record_count} records, {result.attack_linked_count} attack-linked) "
            f"-> {len(result.files)} files"
        )
        for file_path in result.files:
            digest = file_digest(Path(file_path))
            console.print(f"  {file_path} SHA-256: {digest}")

    if stream_by_stage:
        _run_stream_by_stage(bundle.resolve(), events_path, window_start, stage_minutes)


@stage_app.command("bucketize")
def stage_bucketize_command(
    bundle: Annotated[
        Path,
        typer.Option("--bundle", "-b", help="Bundle directory with data/ and grader/"),
    ],
    events: Annotated[
        Path | None,
        typer.Option(
            "--events",
            "-e",
            help="Canonical events path (default: <bundle>/grader/canonical_events.ndjson)",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Agent output root (default: <bundle>/agent)",
        ),
    ] = None,
    window_start: Annotated[
        str | None,
        typer.Option("--window-start", help="Timeline origin for stage bucketing"),
    ] = None,
    stage_minutes: Annotated[
        int,
        typer.Option("--stage-minutes", help="Stage bucket width in minutes"),
    ] = 30,
    stream_by_stage: Annotated[
        bool,
        typer.Option(
            "--stream-by-stage",
            help="Enable stage slicing (kept for parity with dataset build CLI)",
        ),
    ] = True,
) -> None:
    """Slice synthetic sources and canonical events into cumulative agent stages."""
    logging.basicConfig(level=logging.INFO)
    if not stream_by_stage:
        console.print("[yellow]--stream-by-stage not set; nothing to do[/yellow]")
        return
    bundle_dir = bundle.resolve()
    events_path = (events or (bundle_dir / "grader" / CANONICAL_EVENTS_FILENAME)).resolve()
    _run_stream_by_stage(
        bundle_dir,
        events_path,
        window_start,
        stage_minutes,
        agent_root=output,
    )


def _run_stream_by_stage(
    bundle_dir: Path,
    events_path: Path,
    window_start: str | None,
    stage_minutes: int,
    *,
    agent_root: Path | None = None,
) -> None:
    result = bucketize_bundle(
        bundle_dir,
        events_path=events_path,
        agent_root=agent_root,
        window_start=window_start,
        stage_minutes=stage_minutes,
    )
    console.print(
        f"[green]Bucketized {result.stage_count} stages[/green] "
        f"(max_stage={result.max_stage}) -> {result.agent_root}"
    )
    for stage_name, digests in sorted(result.stage_digests.items()):
        if not digests:
            continue
        console.print(f"  {stage_name}: {len(digests)} files")
        for rel_path, digest in sorted(digests.items()):
            console.print(f"    {rel_path} SHA-256: {digest}")


def _load_scenario(path: Path) -> Scenario:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Scenario.model_validate(data)


def _parse_task_list(task: list[str] | None) -> tuple[str, ...]:
    """Expand Typer task options, including comma-separated single tokens."""
    if not task:
        return DEFAULT_TRUTH_TASKS
    expanded: list[str] = []
    for item in task:
        expanded.extend(part.strip().lower() for part in item.split(",") if part.strip())
    return tuple(expanded)


def main() -> None:
    """Run the SOC-bench CLI."""
    app()


if __name__ == "__main__":
    main()
