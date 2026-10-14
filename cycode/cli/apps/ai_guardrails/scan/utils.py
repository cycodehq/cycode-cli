"""
Utility functions for AI guardrails.

Includes JSON parsing, path matching, text handling and hook-message utilities.
"""

import json
import os
import sys
from collections import defaultdict
from gettext import ngettext
from pathlib import Path
from typing import TYPE_CHECKING

from cycode.cli.apps.ai_guardrails.scan.policy import get_policy_value
from cycode.cli.cli_types import SeverityOption
from cycode.cli.utils.string_utils import obfuscate_text

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult
    from cycode.cyclient.models import Detection

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


def _describe_detection(detection: 'Detection', content: str) -> str:
    details = detection.detection_details
    description = detection.type or detection.message

    line = details.get('line')
    if isinstance(line, int) and line >= 0:
        description += f' (line {line + 1})'  # the scanner reports 0-based lines

    start, length = details.get('start_position'), details.get('length')
    if isinstance(start, int) and isinstance(length, int) and start >= 0 and length > 0:
        value = content[start : start + length]
        if value:
            description += f': {obfuscate_text(value)}'

    return description


def build_violation_summary(
    local_scan_results: list['LocalScanResult'], max_lines: int = MAX_VIOLATION_DETAIL_LINES
) -> tuple[str, tuple[str, ...]]:
    """One line per distinct finding (what it is, where, the masked value), and the value hashes to ignore them by.

    The masked value and hash are safe to display; the value itself is not. Detections excluded by an existing
    ignore rule are already gone from `document_detections`, so only what actually blocked is listed.
    """
    # Keyed by value hash so a repeated value is listed once; detections without one key by their description
    finding_by_key = {}
    for local_scan_result in local_scan_results:
        for document_detections in local_scan_result.document_detections:
            for detection in document_detections.detections:
                description = _describe_detection(detection, document_detections.document.content)
                sha = detection.detection_details.get('sha512')
                finding_by_key.setdefault(sha or description, (sha, description))

    listed = list(finding_by_key.values())[:max_lines]
    lines = [_build_severity_line(local_scan_results)] + [f'  - {description}' for _, description in listed]
    remaining = len(finding_by_key) - len(listed)
    if remaining:
        lines.append(f'  - ...and {remaining} more')

    return '\n'.join(lines), tuple(sha for sha, _ in listed if sha)


def _build_severity_line(local_scan_results: list['LocalScanResult']) -> str:
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

    violations = ngettext('violation', 'violations', detections_count)
    return f'Cycode found {detections_count} {violations}: {" | ".join(severity_parts)}'
