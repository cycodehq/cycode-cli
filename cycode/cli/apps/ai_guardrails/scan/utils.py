"""
Utility functions for AI guardrails.

Includes JSON parsing, path matching, and text handling utilities.
"""

import json
import os
from pathlib import Path

from cycode.cli.apps.ai_guardrails.scan.policy import get_policy_value


def safe_json_parse(s: str) -> dict:
    """Parse JSON string, returning empty dict on failure."""
    try:
        return json.loads(s) if s else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def truncate_utf8(text: str, max_bytes: int) -> str:
    """Truncate text to max bytes while preserving valid UTF-8."""
    if not text:
        return ''
    encoded = text.encode('utf-8')
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode('utf-8', errors='ignore')


def normalize_path(file_path: str) -> str:
    """Normalize path to prevent traversal attacks."""
    if not file_path:
        return ''
    normalized = os.path.normpath(file_path)
    # Reject paths that attempt to escape outside bounds
    if normalized.startswith('..'):
        return ''
    return normalized


def matches_glob(file_path: str, pattern: str) -> bool:
    """Check if file path matches a glob pattern.

    Case-insensitive matching for cross-platform compatibility.
    """
    normalized = normalize_path(file_path)
    if not normalized or not pattern:
        return False

    path = Path(normalized)
    # Try case-sensitive first
    if path.match(pattern):
        return True

    # Then try case-insensitive by lowercasing both path and pattern
    path_lower = Path(normalized.lower())
    return path_lower.match(pattern.lower())


def is_denied_path(file_path: str, policy: dict) -> bool:
    """Check if file path is in the denylist."""
    if not file_path:
        return False
    globs = get_policy_value(policy, 'file_read', 'deny_globs', default=[])
    return any(matches_glob(file_path, g) for g in globs)


def output_json(obj: dict) -> None:
    """Write JSON response to stdout (for IDE to read)."""
    print(json.dumps(obj), end='')  # noqa: T201
