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
from socbench.capture.hashing import stable_seed
from socbench.capture.models import CanonicalEvent, ObservationStatus
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

# Record-level candidate sources by GT event kind (per-record, not storyline-wide).
KIND_CANDIDATE_FORMATS: dict[str, list[str]] = {
    "connection": ["zeek_conn", "cisco_asa", "snort_alert", "ecar"],
    "process": [
        "windows_event_sysmon",
        "windows_event_security",
        "ecar",
        "syslog",
        "bash_history",
    ],
    "logon": ["windows_event_security", "ecar", "syslog"],
    "failed_logon": ["windows_event_security", "ecar", "syslog"],
    "logoff": ["windows_event_security", "ecar", "syslog"],
    "ssh_session": ["zeek_conn", "syslog", "ecar", "cisco_asa"],
    "rdp_session": ["zeek_conn", "windows_event_security", "ecar", "cisco_asa"],
    "port_scan": ["zeek_conn", "cisco_asa", "snort_alert", "ecar"],
    "web_scan": ["web_access", "zeek_conn", "cisco_asa", "snort_alert", "ecar"],
    "beacon": ["proxy_access", "zeek_conn", "cisco_asa", "ecar", "windows_event_sysmon"],
    "dns_query": ["zeek_dns", "zeek_conn"],
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
    # Expected behaviour when observation_profile == "complete": EF's loader returns
    # None by design (no missingness to report). Capture then uses
    # GROUND_TRUTH.source_evidence_status and per-record kind candidates instead.
    # That is a normal mode, not a load failure.
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
    data_root = bundle_dir / "data"
    for ordinal, event in enumerate(attack_events):
        storyline_id = event.storyline_id or ""
        spec = storyline_index.get(storyline_id)
        fields = _event_fields(event)
        candidate_formats = candidate_formats_for_record(
            kind=event.kind,
            storyline_id=storyline_id,
            fields=fields,
            manifest=manifest,
            document=document,
        )
        output_refs: dict[str, str] = {}
        if data_root.is_dir():
            stub = CanonicalEvent(
                evidence_id=format_evidence_id(resolved_seed, ordinal),
                ts=_format_ts(event.time),
                host=event.system,
                actor=event.actor,
                kind=event.kind,
                fields=fields,
                record_id=event.record_id,
                storyline_id=event.storyline_id,
            )
            output_refs = resolve_output_refs(stub, data_root, candidate_formats)

        observed_by, unresolved, status = finalize_observation(
            candidate_formats,
            output_refs,
        )
        records.append(
            CanonicalEvent(
                evidence_id=format_evidence_id(resolved_seed, ordinal),
                ts=_format_ts(event.time),
                phase=spec.phase if spec else None,
                attack=list(spec.attack) if spec else [],
                host=event.system,
                actor=event.actor,
                kind=event.kind,
                fields=fields,
                observed_by=observed_by,
                output_refs=output_refs,
                observation_status=status,
                unresolved_sources=unresolved,
                record_id=event.record_id,
                storyline_id=event.storyline_id,
            )
        )

    logger.info(
        "Built %s canonical events from %s using %s (seed=%s)",
        len(records),
        bundle_dir,
        mechanism.value,
        resolved_seed,
    )
    return records


def finalize_observation(
    candidates: list[str],
    output_refs: dict[str, str],
) -> tuple[list[str], list[str], ObservationStatus]:
    """Apply P0-3 symmetry: observed_by mirrors confirmed refs; rest → unresolved.

    Candidates are attempted first (P0-2). Only after an honest resolve attempt
    do unconfirmed sources leave observed_by and land in unresolved_sources.
    """
    confirmed = sorted(output_refs)
    unresolved = [fmt for fmt in candidates if fmt not in output_refs]
    if not candidates:
        status: ObservationStatus = "unobserved"
    elif not confirmed:
        status = "unobserved"
    elif unresolved:
        status = "partial"
    else:
        status = "observed"
    return confirmed, unresolved, status


def resolve_capture_seed(scenario: Scenario, seed: int | None) -> int:
    """Resolve the deterministic seed used for evidence identifiers."""
    if seed is not None:
        return seed
    return stable_seed(f"socbench:{scenario.name}")


def format_evidence_id(seed: int, ordinal: int) -> str:
    """Deterministic evidence id from scenario seed and attack-event ordinal.

    Format: EVID-<8 hex> where hex = sha256(f"{seed}:{ordinal}")[:8].
    Stable for a fixed seed; changes when seed changes; unique per ordinal.
    NDJSON sort order remains (ts, record_id) and does not depend on this id.
    """
    digest = hashlib.sha256(f"{seed}:{ordinal}".encode("utf-8")).hexdigest()[:8]
    return f"EVID-{digest}"


def candidate_formats_for_record(
    *,
    kind: str,
    storyline_id: str,
    fields: dict[str, Any],
    manifest: ObservationManifest | None,
    document: GroundTruthDocument,
) -> list[str]:
    """Return per-record candidate log formats for observation resolution.

    Combines:
    1. Kind-specific formats for this GT record (not shared across multi-record steps)
    2. Storyline-level visible sources (intersection / union with kind when present)
    3. Explicit expected_sources on the record attributes when present
    """
    kind_formats = list(KIND_CANDIDATE_FORMATS.get(kind, []))
    storyline_formats = observed_formats_for_storyline(storyline_id, manifest, document)
    expected = fields.get("expected_sources")
    expected_formats: list[str] = []
    if isinstance(expected, list):
        for item in expected:
            if isinstance(item, str):
                expected_formats.extend(SOURCE_TO_OBSERVED_FORMATS.get(item, [item]))

    # Prefer intersection of kind and storyline when both non-empty; otherwise kind
    # alone (storyline-only inheritance caused multi-record pollution in P0-1 audit).
    if kind_formats and storyline_formats:
        shared = [fmt for fmt in kind_formats if fmt in set(storyline_formats)]
        candidates = shared if shared else kind_formats
    elif kind_formats:
        candidates = kind_formats
    else:
        candidates = storyline_formats

    for fmt in expected_formats:
        if fmt not in candidates:
            candidates.append(fmt)
    return candidates


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
