"""Errors for native host-log conversion."""

from __future__ import annotations


class SocbenchRawError(Exception):
    """Base error for SOC-bench native format conversion."""


class EvtxConversionError(SocbenchRawError):
    """Raised when XML to EVTX conversion fails."""


class JournalConversionError(SocbenchRawError):
    """Raised when syslog to journal conversion fails."""


class JournalBackendUnavailableError(JournalConversionError):
    """Raised when neither Docker nor WSL journal backends are available."""
