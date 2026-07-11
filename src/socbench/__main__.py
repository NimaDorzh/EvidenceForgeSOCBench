"""SOC-bench CLI entrypoint."""

from __future__ import annotations

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
    canonical_events_digest,
    write_canonical_events,
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

app = typer.Typer(no_args_is_help=True, add_completion=False)
truth_app = typer.Typer(no_args_is_help=True, add_completion=False)
app.add_typer(truth_app, name="truth")
console = Console()
logger = logging.getLogger(__name__)

DEFAULT_TRUTH_TASKS = ("fox", "goat", "mouse", "tiger", "panda")


@app.callback()
def cli() -> None:
    """SOC-bench extensions for EvidenceForge."""


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
    digest = canonical_events_digest(events)
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
    selected = {item.lower() for item in (task or list(DEFAULT_TRUTH_TASKS))}

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


def _load_scenario(path: Path) -> Scenario:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Scenario.model_validate(data)


def main() -> None:
    """Run the SOC-bench CLI."""
    app()


if __name__ == "__main__":
    main()
