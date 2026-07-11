"""Local deterministic helpers (no private EvidenceForge RNG imports)."""

from __future__ import annotations

import hashlib
import struct


def stable_seed(key: str) -> int:
    """Derive a stable 32-bit positive seed from an arbitrary string key."""
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return struct.unpack(">I", digest[:4])[0] & 0x7FFFFFFF
