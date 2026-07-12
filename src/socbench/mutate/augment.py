"""Data augmentation for robustness testing without changing truth semantics."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from socbench.capture.hashing import stable_seed
from socbench.sources.common import file_digest, write_source_records
from socbench.sources.models import SourceRecord

_HOST_ALIAS_PATTERN = re.compile(r"\b(WKS-\d+|FS-\d+|FTP-\d+|DC-\d+|VPN-GW-\d+|OT-HMI-\d+)\b")


@dataclass(frozen=True, slots=True)
class AugmentConfig:
    """Configuration for surface-form dataset augmentation."""

    seed: int = 42
    rename_hosts: bool = True
    mutate_helpdesk_text: bool = True
    mutate_cti_indicators: bool = True
    timing_jitter_ms: int = 0


def augment_source_tree(source_root: Path, config: AugmentConfig) -> dict[str, str]:
    """Mutate synthetic source files in place; return before/after digests keyed by path."""
    source_root = source_root.resolve()
    digests_before: dict[str, str] = {}
    digests_after: dict[str, str] = {}

    for path in sorted(source_root.rglob("*.ndjson")):
        digests_before[str(path)] = file_digest(path)
        records = _load_records(path)
        mutated = [_mutate_record(record, config) for record in records]
        write_source_records(path, mutated)
        digests_after[str(path)] = file_digest(path)

    return {
        "before": json.dumps(digests_before, sort_keys=True),
        "after": json.dumps(digests_after, sort_keys=True),
    }


def build_host_alias_map(hosts: list[str], seed: int) -> dict[str, str]:
    """Build deterministic host alias mapping that preserves host role prefixes."""
    from random import Random

    rng = Random(stable_seed(f"augment_hosts:{seed}"))
    aliases: dict[str, str] = {}
    for host in sorted(set(hosts)):
        prefix = host.rsplit("-", maxsplit=1)[0]
        suffix = host.rsplit("-", maxsplit=1)[-1]
        alias_suffix = str(int(suffix) + rng.randint(10, 99)) if suffix.isdigit() else suffix
        aliases[host] = f"{prefix}-{alias_suffix}"
    return aliases


def _load_records(path: Path) -> list[SourceRecord]:
    records: list[SourceRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        payload = json.loads(stripped)
        metadata_raw = payload.pop("__grader_metadata", None)
        grader_metadata = None
        if metadata_raw is not None:
            from socbench.sources.models import GraderMetadata

            grader_metadata = GraderMetadata.model_validate(metadata_raw)
        records.append(SourceRecord(payload=payload, grader_metadata=grader_metadata))
    return records


def _mutate_record(record: SourceRecord, config: AugmentConfig) -> SourceRecord:
    payload = dict(record.payload)
    metadata = record.grader_metadata

    if config.rename_hosts:
        alias_map = build_host_alias_map(_hosts_in_payload(payload), config.seed)
        payload = _apply_host_aliases(payload, alias_map)

    if (
        config.mutate_helpdesk_text
        and "ticket_id" in payload
        and isinstance(payload.get("text"), str)
    ):
        payload["text"] = _mutate_helpdesk_text(
            str(payload["text"]), config.seed, payload["ticket_id"]
        )

    if config.mutate_cti_indicators and payload.get("feed", "").startswith("trap_noise"):
        indicator = payload.get("indicator")
        if isinstance(indicator, str):
            payload["indicator"] = _mutate_trap_indicator(
                indicator, config.seed, str(payload.get("record_id", ""))
            )

    if config.timing_jitter_ms > 0 and isinstance(payload.get("ts"), str):
        payload["ts"] = _jitter_ts(
            str(payload["ts"]), config.seed, str(payload.get("record_id", ""))
        )

    return SourceRecord(payload=payload, grader_metadata=metadata)


def _hosts_in_payload(payload: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    for key in ("host", "related_host"):
        value = payload.get(key)
        if isinstance(value, str):
            hosts.append(value)
    correlated = payload.get("correlated_hosts")
    if isinstance(correlated, list):
        hosts.extend(str(item) for item in correlated)
    return hosts


def _apply_host_aliases(payload: dict[str, Any], alias_map: dict[str, str]) -> dict[str, Any]:
    mutated = dict(payload)
    for key in ("host", "related_host"):
        value = mutated.get(key)
        if isinstance(value, str) and value in alias_map:
            mutated[key] = alias_map[value]
    correlated = mutated.get("correlated_hosts")
    if isinstance(correlated, list):
        mutated["correlated_hosts"] = [alias_map.get(str(item), str(item)) for item in correlated]
    for text_key in ("text", "summary", "message"):
        value = mutated.get(text_key)
        if isinstance(value, str):
            mutated[text_key] = _HOST_ALIAS_PATTERN.sub(
                lambda match: alias_map.get(match.group(1), match.group(1)),
                value,
            )
    return mutated


def _mutate_helpdesk_text(text: str, seed: int, ticket_id: str) -> str:
    variants = [
        text,
        text.replace("reports", "reported"),
        text.replace("desktop", "screen"),
        f"[AUTO] {text}",
    ]
    from random import Random

    rng = Random(stable_seed(f"augment_helpdesk:{seed}:{ticket_id}"))
    return variants[rng.randint(0, len(variants) - 1)]


def _mutate_trap_indicator(indicator: str, seed: int, record_id: str) -> str:
    from random import Random

    rng = Random(stable_seed(f"augment_cti:{seed}:{record_id}"))
    if indicator.count(".") == 3:
        parts = indicator.split(".")
        parts[-1] = str((int(parts[-1]) + rng.randint(1, 5)) % 254 + 1)
        return ".".join(parts)
    return f"{indicator}-mut{rng.randint(1, 9)}"


def _jitter_ts(ts: str, seed: int, record_id: str) -> str:
    from datetime import timedelta
    from random import Random

    from socbench.truth.common import parse_ts

    rng = Random(stable_seed(f"augment_ts:{seed}:{record_id}"))
    jitter_ms = rng.randint(-300_000, 300_000)
    shifted = parse_ts(ts) + timedelta(milliseconds=jitter_ms)
    return shifted.strftime("%Y-%m-%dT%H:%M:%SZ")
