"""Pydantic models for SOC-bench synthetic source records."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class GraderMetadata(BaseModel):
    """Hidden grader linkage block stripped from agent exports (DP2 gate, step 6)."""

    linked_evidence_ids: list[str] = Field(default_factory=list)
    latency_applied_ms: int = 0
    template_id: str = ""


class SourceBuildConfig(BaseModel):
    """Configuration for building all synthetic SOC-bench sources."""

    seed: int = 42
    window_start: str | None = None
    stage_minutes: int = 30
    helpdesk_min_stage: int | None = None
    helpdesk_base_latency_ms: int = 1_800_000
    llm_enabled: bool = False
    llm_cache_path: str | None = None

    model_config = ConfigDict(extra="forbid")


class SourceBuildResult(BaseModel):
    """Summary of files written by a source builder."""

    source_name: str
    files: list[str] = Field(default_factory=list)
    record_count: int = 0
    attack_linked_count: int = 0

    model_config = ConfigDict(extra="forbid")


class SourceRecord(BaseModel):
    """One NDJSON source record with optional grader metadata."""

    payload: dict[str, Any]
    grader_metadata: GraderMetadata | None = None

    model_config = ConfigDict(extra="forbid")

    def to_ndjson_dict(self) -> dict[str, Any]:
        """Serialize to NDJSON dict, embedding ``__grader_metadata`` when present."""
        row = dict(self.payload)
        if self.grader_metadata is not None:
            row["__grader_metadata"] = self.grader_metadata.model_dump(mode="json")
        return row
