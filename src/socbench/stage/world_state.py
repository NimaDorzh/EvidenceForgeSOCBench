"""World-state abstraction for per-stage truth projection (static v1 + interactive seam)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from socbench.capture.models import CanonicalEvent
from socbench.truth.common import (
    DEFAULT_STAGE_MINUTES,
    events_through_stage,
    infer_window_start,
    parse_ts,
    stage_of,
)


@dataclass(frozen=True, slots=True)
class Intervention:
    """Containment command issued by an agent in optional interactive mode."""

    kind: str
    targets: list[str]
    at_stage: int


class WorldState(Protocol):
    """Read-only view of incident evidence with optional interactive patching."""

    def slice_through(self, stage: int) -> list[CanonicalEvent]:
        """Return cumulative canonical events through the requested stage."""

    def apply(self, intervention: Intervention) -> WorldState:
        """Apply a containment intervention and return updated world state."""

    def replan_tail(self, from_stage: int) -> list[CanonicalEvent]:
        """Return tail events after optional replanning from a stage boundary."""


@dataclass
class StaticWorldState:
    """Identity world state for static datasets (apply/replan are no-ops)."""

    events: list[CanonicalEvent]
    window_start: datetime
    stage_minutes: int = DEFAULT_STAGE_MINUTES
    interventions: tuple[Intervention, ...] = field(default_factory=tuple)

    @classmethod
    def from_events(
        cls,
        events: list[CanonicalEvent],
        *,
        window_start: str | datetime | None = None,
        stage_minutes: int = DEFAULT_STAGE_MINUTES,
    ) -> StaticWorldState:
        """Build a static world state from canonical events."""
        if window_start is None:
            origin = infer_window_start(events)
        elif isinstance(window_start, str):
            origin = parse_ts(window_start)
        else:
            origin = window_start.astimezone(UTC)
        return cls(events=events, window_start=origin, stage_minutes=stage_minutes)

    def slice_through(self, stage: int) -> list[CanonicalEvent]:
        """Return cumulative canonical events through the requested stage."""
        return events_through_stage(
            self.events,
            stage,
            self.window_start,
            stage_minutes=self.stage_minutes,
        )

    def apply(self, intervention: Intervention) -> StaticWorldState:
        """No-op in static mode; record intervention for interface compatibility."""
        return StaticWorldState(
            events=self.events,
            window_start=self.window_start,
            stage_minutes=self.stage_minutes,
            interventions=(*self.interventions, intervention),
        )

    def replan_tail(self, from_stage: int) -> list[CanonicalEvent]:
        """Return the unchanged tail in static mode (no EF re-run)."""
        return [
            event
            for event in self.events
            if stage_of(event.ts, self.window_start, stage_minutes=self.stage_minutes) >= from_stage
        ]


def world_state_from_events(
    events: list[CanonicalEvent],
    *,
    window_start: str | datetime | None = None,
    stage_minutes: int = DEFAULT_STAGE_MINUTES,
) -> StaticWorldState:
    """Construct the default static world state wrapper."""
    return StaticWorldState.from_events(
        events,
        window_start=window_start,
        stage_minutes=stage_minutes,
    )
