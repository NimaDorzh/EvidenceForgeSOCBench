"""Scenario YAML helpers for enriching canonical events."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from evidenceforge.models.scenario import Scenario

_TECHNIQUE_ID = re.compile(r"^(T\d+(?:\.\d+)*)")

_DISCOVERY_PREFIXES = (
    "T1005",
    "T1016",
    "T1018",
    "T1033",
    "T1046",
    "T1049",
    "T1057",
    "T1069",
    "T1082",
    "T1083",
    "T1087",
    "T1552",
)


@dataclass(frozen=True, slots=True)
class StorylineSpecIndex:
    """Per-storyline metadata derived from scenario YAML."""

    storyline_id: str
    index: int
    phase: str | None
    attack: list[str] = field(default_factory=list)


def build_storyline_index(scenario: Scenario) -> dict[str, StorylineSpecIndex]:
    """Build a lookup table keyed by storyline event id."""
    index: dict[str, StorylineSpecIndex] = {}
    for step_index, step in enumerate(scenario.storyline or []):
        attack_ids: list[str] = []
        phase: str | None = None
        for spec in step.events:
            attack_ids.extend(parse_attack_ids(getattr(spec, "technique", None)))
            spec_phase = getattr(spec, "phase", None)
            if spec_phase:
                phase = str(spec_phase)
        if phase is None:
            phase = infer_phase(step_index, attack_ids)
        index[step.id] = StorylineSpecIndex(
            storyline_id=step.id,
            index=step_index,
            phase=phase,
            attack=_dedupe(attack_ids),
        )
    return index


def parse_attack_ids(technique: str | None) -> list[str]:
    """Extract ATT&CK technique ids from a scenario technique string."""
    if not technique:
        return []
    match = _TECHNIQUE_ID.match(technique.strip())
    return [match.group(1)] if match else []


def infer_phase(storyline_index: int, attack_ids: list[str]) -> str:
    """Infer a coarse attack phase when the scenario omits an explicit phase."""
    if storyline_index == 0:
        return "initial_access"
    if any(attack_id.startswith(_DISCOVERY_PREFIXES) for attack_id in attack_ids):
        return "discovery"
    return "execution"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
