"""Pydantic models for grader-facing canonical event records."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ObservationStatus = Literal["observed", "unobserved", "partial"]


class CanonicalEvent(BaseModel):
    """One grader-facing canonical evidence record."""

    evidence_id: str
    ts: str
    phase: str | None = None
    attack: list[str] = Field(default_factory=list)
    host: str
    actor: str
    kind: str
    fields: dict[str, Any] = Field(default_factory=dict)
    observed_by: list[str] = Field(default_factory=list)
    output_refs: dict[str, str] = Field(default_factory=dict)
    observation_status: ObservationStatus = "unobserved"
    unresolved_sources: list[str] = Field(default_factory=list)
    record_id: str
    storyline_id: str | None = None

    model_config = ConfigDict(extra="forbid")
