"""
API Manager Module - Stub (API providers removed)

All online API provider support has been removed.
Only Ollama local models are supported.
"""


def query(provider: str, prompt: str, **kwargs) -> str:
    """Stub - API providers not supported. Returns empty string."""
    return ""


def validate_api_key(provider: str, key: str) -> bool:
    """Stub - API providers not supported."""
    return False


def get_configured_providers() -> list:
    """Stub - no API providers configured."""
    return []
