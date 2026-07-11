"""SOC-bench capture errors."""

from __future__ import annotations


class SocbenchCaptureError(Exception):
    """Raised when canonical-event capture cannot proceed safely."""
