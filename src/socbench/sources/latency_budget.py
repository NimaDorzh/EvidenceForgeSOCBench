"""Forward observation-latency budgets for synthetic SOC-bench sources.

These ``*_MAX_LATENCY_MS`` values are **contractual upper bounds**: every source
builder that calls ``apply_latency(event.ts, offset_ms)`` must keep
``offset_ms <=`` the matching constant (or ``<= max_forward_source_latency_ms``
overall). Randomized latencies must draw from ``[min, CONSTANT]`` using the
shared constant imported from this module — not ad-hoc literals.

``validate_agent_stage_count_aligned`` derives allowed agent/grader stage slack
from these bounds via ``allowed_agent_stage_slack(stage_minutes)``. When a
contract changes, update the constant here **and** the builder import site;
``tests/socbench/test_latency_budget.py`` guards the relationship.

Trap CTI feeds use ``pre_scenario_ts`` (historical IOC noise before the window)
and do not contribute to forward stage slack.
"""

from __future__ import annotations

import math

from socbench.sources.models import SourceBuildConfig

# Contractual forward-latency ceilings (milliseconds).
SIEM_RULE_MAX_LATENCY_MS = 300_000
XDR_MIN_LATENCY_MS = 30_000
XDR_MAX_LATENCY_MS = 150_000
CTI_RELEVANT_MIN_LATENCY_MS = 600_000
CTI_RELEVANT_MAX_LATENCY_MS = 3_600_000
VSS_MIN_LATENCY_MS = 30_000
VSS_MAX_LATENCY_MS = 120_000
HELPDESK_LATENCY_MIN_MS = 60_000
HELPDESK_NEGATIVE_JITTER_MS = 300_000
HELPDESK_LATENCY_JITTER_MS = 900_000


def clamp_forward_latency_ms(latency_ms: int, *, ceiling_ms: int) -> int:
    """Clamp a forward latency offset to a contractual ceiling."""
    return min(max(0, latency_ms), ceiling_ms)


def max_forward_source_latency_ms(config: SourceBuildConfig | None = None) -> int:
    """Return the largest contractual forward latency (ms) any source may apply."""
    helpdesk_base = SourceBuildConfig().helpdesk_base_latency_ms
    if config is not None:
        helpdesk_base = config.helpdesk_base_latency_ms
    helpdesk_max = helpdesk_base + HELPDESK_LATENCY_JITTER_MS
    return max(
        SIEM_RULE_MAX_LATENCY_MS,
        XDR_MAX_LATENCY_MS,
        CTI_RELEVANT_MAX_LATENCY_MS,
        VSS_MAX_LATENCY_MS,
        helpdesk_max,
    )


def allowed_agent_stage_slack(
    stage_minutes: int,
    *,
    config: SourceBuildConfig | None = None,
) -> int:
    """Stages agent bucketization may extend past grader staged manifests."""
    if stage_minutes <= 0:
        return 0
    stage_duration_ms = stage_minutes * 60_000
    return math.ceil(max_forward_source_latency_ms(config) / stage_duration_ms)
