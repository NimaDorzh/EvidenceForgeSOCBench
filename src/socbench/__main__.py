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

app = typer.Typer(no_args_is_help=True, add_completion=False)
console = Console()
logger = logging.getLogger(__name__)


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


def _load_scenario(path: Path) -> Scenario:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Scenario.model_validate(data)


def main() -> None:
    """Run the SOC-bench CLI."""
    app()


if __name__ == "__main__":
    main()
