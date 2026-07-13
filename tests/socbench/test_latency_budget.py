"""Tests for source forward-latency budget helpers."""

from __future__ import annotations

from socbench.sources.latency_budget import (
    CTI_RELEVANT_MAX_LATENCY_MS,
    SIEM_RULE_MAX_LATENCY_MS,
    allowed_agent_stage_slack,
    max_forward_source_latency_ms,
)
from socbench.sources.models import SourceBuildConfig
from socbench.sources.siem import _default_rules


def test_max_forward_source_latency_is_dominated_by_cti_cap() -> None:
    assert max_forward_source_latency_ms() == CTI_RELEVANT_MAX_LATENCY_MS


def test_allowed_agent_stage_slack_derived_from_cti_latency_at_30m_stages() -> None:
    # CTI relevant latency upper bound is 1 hour; 30-minute stages => 2-stage slack.
    assert allowed_agent_stage_slack(30) == 2


def test_allowed_agent_stage_slack_scales_inversely_with_stage_minutes() -> None:
    """Shorter stages widen slack; no hardcoded stage_minutes=30 elsewhere."""
    assert allowed_agent_stage_slack(60) == 1
    assert allowed_agent_stage_slack(30) == 2
    assert allowed_agent_stage_slack(15) == 4
    assert allowed_agent_stage_slack(15) == allowed_agent_stage_slack(30) * 2


def test_allowed_agent_stage_slack_respects_helpdesk_config_increase() -> None:
    config = SourceBuildConfig(helpdesk_base_latency_ms=3_600_000)
    assert max_forward_source_latency_ms(config) == 3_600_000 + 900_000
    assert allowed_agent_stage_slack(30, config=config) == 3


def test_siem_rules_respect_contractual_latency_ceiling() -> None:
    for rule in _default_rules():
        assert rule.latency_ms <= SIEM_RULE_MAX_LATENCY_MS, (
            f"rule {rule.rule_id} latency {rule.latency_ms}ms exceeds contractual "
            f"ceiling {SIEM_RULE_MAX_LATENCY_MS}ms; update latency_budget.py"
        )
