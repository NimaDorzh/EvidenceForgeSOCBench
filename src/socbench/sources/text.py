"""Deterministic text rendering and optional LLM cache for source records."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

from socbench.sources.errors import UncachedLlmCallError

_TEMPLATE_VARIANTS: dict[str, tuple[str, ...]] = {
    "vss_delete_shadows_v1": (
        "Volume Shadow Copy service reported deletion of all shadow copies on {host} "
        "by {process_name} (pid {pid}).",
        "Backup subsystem log: shadow copy purge on {host}; command matched 'delete shadows /all'.",
    ),
    "ransom_note_v1": (
        "User {user} on {host} reports files renamed and unreadable; ransom note on desktop.",
        "Helpdesk: {user}@{host} — documents show new extension, desktop note present.",
    ),
    "ransom_note_v2": (
        "Cannot open spreadsheets on {host}; wallpaper changed to payment instructions.",
        "Files on {host} for {user} encrypted; recovery note left on desktop.",
    ),
    "ransom_note_v3": (
        "Files renamed and will not open on {host}; ransom note on desktop for {user}.",
        "Multiple users on {host} report encrypted shares and a desktop recovery note.",
    ),
    "cti_ioc_v1": (
        "Observed outbound connection to {indicator} from internal host during incident window.",
        "Threat feed match: {indicator_type} {indicator} correlated with lateral movement.",
    ),
    "siem_alert_v1": (
        "Rule {rule_id} fired on {host}: {summary}",
        "Correlation alert {rule_id} — {severity} on {host}: {summary}",
    ),
    "xdr_anomaly_v1": (
        "XDR anomaly on {host}: {anomaly_type} score {score}",
        "Endpoint anomaly {anomaly_type} detected on {host} (score {score}).",
    ),
}


class LlmTextCache:
    """Disk-backed cache for optional LLM paraphrasing keyed by deterministic inputs."""

    def __init__(self, path: Path | None) -> None:
        self._path = path.resolve() if path is not None else None
        self._memory: dict[str, str] = {}
        self._lock = threading.Lock()
        if self._path is not None and self._path.is_file():
            self._memory = json.loads(self._path.read_text(encoding="utf-8"))

    @staticmethod
    def cache_key(
        seed: int,
        template_id: str,
        linked_evidence_ids: list[str],
    ) -> str:
        """Build stable cache key from seed, template, and linked evidence ids."""
        joined = "|".join(sorted(linked_evidence_ids))
        digest = hashlib.sha256(f"{seed}:{template_id}:{joined}".encode()).hexdigest()
        return digest

    def get(
        self,
        seed: int,
        template_id: str,
        linked_evidence_ids: list[str],
    ) -> str | None:
        key = self.cache_key(seed, template_id, linked_evidence_ids)
        return self._memory.get(key)

    def put(
        self,
        seed: int,
        template_id: str,
        linked_evidence_ids: list[str],
        text: str,
    ) -> None:
        key = self.cache_key(seed, template_id, linked_evidence_ids)
        with self._lock:
            self._memory[key] = text
            if self._path is not None:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._path.write_text(
                    json.dumps(self._memory, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )


class _LlmGuard:
    """Process-local guard that forbids uncached LLM calls in the data path."""

    _active: bool = False
    _allow_cache_hit: bool = False

    @classmethod
    def enter(cls, *, llm_enabled: bool) -> None:
        cls._active = llm_enabled
        cls._allow_cache_hit = False

    @classmethod
    def leave(cls) -> None:
        cls._active = False
        cls._allow_cache_hit = False

    @classmethod
    def mark_cache_hit(cls) -> None:
        cls._allow_cache_hit = True

    @classmethod
    def assert_llm_call_allowed(cls) -> None:
        if cls._active and not cls._allow_cache_hit:
            msg = (
                "Uncached LLM call blocked in source data path. "
                "Enable llm_cache_path or disable llm_enabled."
            )
            raise UncachedLlmCallError(msg)


def render_template_text(
    template_id: str,
    *,
    seed: int,
    linked_evidence_ids: list[str],
    slots: dict[str, Any],
    llm_enabled: bool = False,
    llm_cache: LlmTextCache | None = None,
) -> str:
    """Render deterministic template text; optional LLM path requires cache hit."""
    if llm_enabled:
        _LlmGuard.enter(llm_enabled=True)
        try:
            if llm_cache is not None:
                cached = llm_cache.get(seed, template_id, linked_evidence_ids)
                if cached is not None:
                    _LlmGuard.mark_cache_hit()
                    return cached
            _LlmGuard.assert_llm_call_allowed()
        finally:
            _LlmGuard.leave()

    variants = _TEMPLATE_VARIANTS.get(template_id)
    if variants is None:
        msg = f"Unknown template_id: {template_id}"
        raise KeyError(msg)

    variant_index = stable_variant_index(seed, template_id, linked_evidence_ids, len(variants))
    template = variants[variant_index]
    try:
        return template.format(**slots)
    except KeyError as exc:
        msg = f"Missing slot {exc.args[0]!r} for template {template_id!r}"
        raise KeyError(msg) from exc


def stable_variant_index(
    seed: int,
    template_id: str,
    linked_evidence_ids: list[str],
    variant_count: int,
) -> int:
    """Pick a deterministic template variant index."""
    joined = "|".join(sorted(linked_evidence_ids))
    digest = hashlib.sha256(f"{seed}:{template_id}:{joined}".encode()).hexdigest()
    return int(digest[:8], 16) % variant_count
