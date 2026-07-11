"""Post-generation canonical event capture (EvidenceForge extension path #2)."""

from __future__ import annotations

import hashlib
import json
import logging
from enum import StrEnum
from pathlib import Path
from typing import Any

from evidenceforge.events.ground_truth import GroundTruthDocument, load_ground_truth_document
from evidenceforge.events.observation_manifest import ObservationManifest, load_observation_manifest
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.paths import safe_write_text
from evidenceforge.utils.rng import _stable_seed
from socbench.capture.models import CanonicalEvent
from socbench.capture.output_refs import resolve_output_refs
from socbench.capture.scenario_index import build_storyline_index

logger = logging.getLogger(__name__)

CANONICAL_EVENTS_FILENAME = "canonical_events.ndjson"

SOURCE_TO_OBSERVED_FORMATS: dict[str, list[str]] = {
    "zeek": ["zeek_conn"],
    "sysmon": ["windows_event_sysmon"],
    "windows_security": ["windows_event_security"],
    "ecar": ["ecar"],
    "syslog": ["syslog"],
    "bash_history": ["bash_history"],
    "proxy": ["proxy_access"],
    "web": ["web_access"],
    "asa": ["cisco_asa"],
    "ids": ["snort_alert"],
}


class CaptureMechanism(StrEnum):
    """How canonical events are collected from EvidenceForge."""

    EXTERNAL_EMITTER = "external_emitter"
    POST_GENERATION = "post_generation"
    GENERATION_MIDDLEWARE = "generation_middleware"


def build_canonical_events(
    bundle_dir: Path,
    scenario: Scenario,
    *,
    seed: int | None = None,
    mechanism: CaptureMechanism = CaptureMechanism.POST_GENERATION,
) -> list[CanonicalEvent]:
    """Build canonical attack-event records from a generated EF bundle."""
    bundle_dir = bundle_dir.resolve()
    document = _require_ground_truth(bundle_dir, scenario)
    manifest = load_observation_manifest(bundle_dir, scenario)
    storyline_index = build_storyline_index(scenario)
    resolved_seed = resolve_capture_seed(scenario, seed)

    attack_events = [
        event
        for event in document.events
        if event.ground_truth_section == "storyline" and event.emitted
    ]
    attack_events.sort(key=lambda event: (event.time, event.record_id))

    records: list[CanonicalEvent] = []
    for ordinal, event in enumerate(attack_events):
        storyline_id = event.storyline_id or ""
        spec = storyline_index.get(storyline_id)
        fields = _event_fields(event)
        observed_formats = observed_formats_for_storyline(
            storyline_id,
            manifest,
            document,
        )
        canonical = CanonicalEvent(
            evidence_id=format_evidence_id(resolved_seed, ordinal),
            ts=_format_ts(event.time),
            phase=spec.phase if spec else None,
            attack=list(spec.attack) if spec else [],
            host=event.system,
            actor=event.actor,
            kind=event.kind,
            fields=fields,
            observed_by=observed_formats,
            output_refs={},
            record_id=event.record_id,
            storyline_id=event.storyline_id,
        )
        data_root = bundle_dir / "data"
        if data_root.is_dir():
            canonical = canonical.model_copy(
                update={
                    "output_refs": resolve_output_refs(canonical, data_root, observed_formats),
                }
            )
        records.append(canonical)

    logger.info(
        "Built %s canonical events from %s using %s (seed=%s)",
        len(records),
        bundle_dir,
        mechanism.value,
        resolved_seed,
    )
    return records


def resolve_capture_seed(scenario: Scenario, seed: int | None) -> int:
    """Resolve the deterministic seed used for evidence identifiers."""
    if seed is not None:
        return seed
    return _stable_seed(f"socbench:{scenario.name}") & 0x7FFFFFFF


def format_evidence_id(seed: int, ordinal: int) -> str:
    """Deterministic evidence id from scenario seed and attack-event ordinal."""
    _ = seed  # reserved for future seed-mixed schemes; ordinal is stable today
    return f"EVID-{ordinal:06d}"


def observed_formats_for_storyline(
    storyline_id: str,
    manifest: ObservationManifest | None,
    document: GroundTruthDocument,
) -> list[str]:
    """Map EF source-observation status to grader-facing format names."""
    source_status = _storyline_source_status(storyline_id, manifest, document)
    observed: list[str] = []
    seen: set[str] = set()
    for source, counts in sorted(source_status.items()):
        visible = counts.get("visible", 0) + counts.get("delayed", 0)
        if visible <= 0:
            continue
        for fmt in SOURCE_TO_OBSERVED_FORMATS.get(source, []):
            if fmt in seen:
                continue
            seen.add(fmt)
            observed.append(fmt)
    return observed


def write_canonical_events(
    events: list[CanonicalEvent],
    output_path: Path,
) -> Path:
    """Write canonical events as NDJSON."""
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [event.model_dump(mode="json", exclude_none=True) for event in events]
    payload = "\n".join(json.dumps(line, sort_keys=True) for line in lines)
    if payload:
        payload += "\n"
    safe_write_text(output_path, payload, encoding="utf-8")
    return output_path


def canonical_events_digest(events: list[CanonicalEvent]) -> str:
    """Return a stable SHA-256 digest for reproducibility checks."""
    lines = [
        json.dumps(event.model_dump(mode="json", exclude_none=True), sort_keys=True)
        for event in events
    ]
    payload = "\n".join(lines)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _require_ground_truth(bundle_dir: Path, scenario: Scenario) -> GroundTruthDocument:
    document = load_ground_truth_document(bundle_dir, scenario)
    if document is None:
        msg = f"GROUND_TRUTH.json not found or invalid for bundle {bundle_dir}"
        raise FileNotFoundError(msg)
    return document


def _storyline_source_status(
    storyline_id: str,
    manifest: ObservationManifest | None,
    document: GroundTruthDocument,
) -> dict[str, dict[str, int]]:
    if manifest is not None:
        event = manifest.storyline_by_id().get(storyline_id)
        if event is not None and event.source_status:
            return event.source_status
    return document.source_evidence_status.get(storyline_id, {})


def _event_fields(event: Any) -> dict[str, Any]:
    attributes = getattr(event, "attributes", None)
    if attributes is None:
        return {}
    if hasattr(attributes, "model_dump"):
        return attributes.model_dump(mode="json", exclude_none=True)
    if isinstance(attributes, dict):
        return {key: value for key, value in attributes.items() if value is not None}
    return {}


def _format_ts(value: Any) -> str:
    if hasattr(value, "isoformat"):
        text = value.isoformat()
        return text.replace("+00:00", "Z")
    return str(value)
