import os
from collections import defaultdict
from typing import TYPE_CHECKING, Optional
from uuid import UUID, uuid4

import typer

from cycode.cli import consts
from cycode.cli.cli_types import SeverityOption

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult
    from cycode.cyclient.models import ScanConfiguration

# Keeps the hook message readable when a single file trips dozens of detections
MAX_VIOLATION_DETAIL_LINES = 5


def set_issue_detected(ctx: typer.Context, issue_detected: bool) -> None:
    ctx.obj['issue_detected'] = issue_detected


def set_issue_detected_by_scan_results(ctx: typer.Context, scan_results: list['LocalScanResult']) -> None:
    set_issue_detected(ctx, any(scan_result.issue_detected for scan_result in scan_results))


def is_scan_failed(ctx: typer.Context) -> bool:
    did_fail = ctx.obj.get('did_fail')
    issue_detected = ctx.obj.get('issue_detected')
    return did_fail or issue_detected


def is_cycodeignore_allowed_by_scan_config(ctx: typer.Context) -> bool:
    scan_config: Optional[ScanConfiguration] = ctx.obj.get('scan_config')
    return scan_config.is_cycode_ignore_allowed if scan_config else True


def should_use_presigned_upload(scan_type: str) -> bool:
    return scan_type in consts.PRESIGNED_UPLOAD_SCAN_TYPES


def generate_unique_scan_id() -> UUID:
    if 'PYTEST_TEST_UNIQUE_ID' in os.environ:
        return UUID(os.environ['PYTEST_TEST_UNIQUE_ID'])

    return uuid4()


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
