"""SOC-bench source generation errors."""


class SocbenchSourceError(Exception):
    """Raised when source generation fails."""


class UncachedLlmCallError(SocbenchSourceError):
    """Raised when an LLM call is attempted without a cache hit."""
