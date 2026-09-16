"""
Utility functions for AI guardrails.

Includes JSON parsing, path matching, text handling and hook-message utilities.
"""

import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

from cycode.cli.apps.ai_guardrails.scan.policy import get_policy_value
from cycode.cli.cli_types import SeverityOption

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult

# Keeps the hook message readable when a single file trips dozens of detections
MAX_VIOLATION_DETAIL_LINES = 5


def read_stdin_text() -> str:
    """Read the hook payload from stdin as UTF-8 text.

    Reads bytes and decodes with utf-8-sig: hook payloads are UTF-8 JSON, but on Windows
    Python decodes piped stdin with the ANSI code page (mojibake for non-ASCII prompts),
    and Cursor on Windows prefixes the payload with a UTF-8 BOM - the -sig codec strips it.
    """
    buffer = getattr(sys.stdin, 'buffer', None)
    if buffer is not None:
        return buffer.read().decode('utf-8-sig', errors='replace')
    # No .buffer (tests mocking sys.stdin with StringIO, exotic streams) - text-mode fallback.
    # lstrip the BOM here too: an already-decoded stream leaves it as U+FEFF, which json.loads
    # rejects (and .strip() doesn't remove - it is not whitespace).
    return sys.stdin.read().lstrip('\ufeff')


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


def _build_detection_lines(
    local_scan_results: list['LocalScanResult'], max_lines: int = MAX_VIOLATION_DETAIL_LINES
) -> str:
    """One line per distinct finding: what it is, and the value hash identifying it.

    The value hash is safe to display; the value itself is not. Detections excluded by an existing
    ignore rule are already gone from `document_detections`, so only what actually blocked is listed.
    """
    type_by_sha = {}
    for local_scan_result in local_scan_results:
        for document_detections in local_scan_result.document_detections:
            for detection in document_detections.detections:
                sha = detection.detection_details.get('sha512')
                if sha and sha not in type_by_sha:
                    type_by_sha[sha] = detection.type or detection.message

    if not type_by_sha:
        return ''

    lines = [f'  - {detection_type}: {sha}' for sha, detection_type in list(type_by_sha.items())[:max_lines]]
    remaining = len(type_by_sha) - len(lines)
    if remaining:
        lines.append(f'  - ...and {remaining} more')

    return '\n' + '\n'.join(lines)


def build_violation_summary(local_scan_results: list['LocalScanResult']) -> str:
    """Build violation summary string with severity breakdown and emojis."""
    detections_count = 0
    severity_counts = defaultdict(int)

    for local_scan_result in local_scan_results:
        for document_detections in local_scan_result.document_detections:
            for detection in document_detections.detections:
                if detection.severity:
                    detections_count += 1
                    severity_counts[SeverityOption(detection.severity)] += 1

    severity_parts = []
    for severity in reversed(SeverityOption):
        emoji = SeverityOption.get_member_unicode_emoji(severity)
        count = severity_counts[severity]
        severity_parts.append(f'{emoji} {severity.upper()} - {count}')

    summary = f'Cycode found {detections_count} violations: {" | ".join(severity_parts)}'
    return summary + _build_detection_lines(local_scan_results)
