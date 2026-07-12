"""Orchestration for all SOC-bench synthetic sources."""

from __future__ import annotations

from pathlib import Path

from socbench.capture.models import CanonicalEvent
from socbench.sources.common import SOURCE_NAMES, load_events
from socbench.sources.cti import build_cti_source
from socbench.sources.helpdesk import build_helpdesk_source
from socbench.sources.hostmetrics import build_hostmetrics_source
from socbench.sources.models import SourceBuildConfig, SourceBuildResult
from socbench.sources.siem import build_siem_source
from socbench.sources.vss import build_vss_source

_BUILDERS = {
    "siem": build_siem_source,
    "hostmetrics": build_hostmetrics_source,
    "vss": build_vss_source,
    "helpdesk": build_helpdesk_source,
    "cti": build_cti_source,
}


def build_sources(
    events: list[CanonicalEvent],
    data_root: Path,
    config: SourceBuildConfig,
    *,
    selected: tuple[str, ...] = SOURCE_NAMES,
) -> list[SourceBuildResult]:
    """Build selected synthetic sources under ``data_root``."""
    data_root = data_root.resolve()
    results: list[SourceBuildResult] = []
    for name in selected:
        builder = _BUILDERS.get(name)
        if builder is None:
            msg = f"Unknown source: {name}"
            raise KeyError(msg)
        results.append(builder(events, data_root, config))
    return results


def build_sources_from_file(
    events_path: Path,
    data_root: Path,
    config: SourceBuildConfig,
    *,
    selected: tuple[str, ...] = SOURCE_NAMES,
) -> list[SourceBuildResult]:
    """Load canonical events and build synthetic sources."""
    events = load_events(events_path)
    return build_sources(events, data_root, config, selected=selected)
