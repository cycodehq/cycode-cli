import os
from collections import defaultdict
from typing import TYPE_CHECKING, Optional
from uuid import UUID, uuid4

import typer

from cycode.cli.cli_types import SeverityOption

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult
    from cycode.cyclient.models import ScanConfiguration


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


def generate_unique_scan_id() -> UUID:
    if 'PYTEST_TEST_UNIQUE_ID' in os.environ:
        return UUID(os.environ['PYTEST_TEST_UNIQUE_ID'])

    return uuid4()


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

    return f'Cycode found {detections_count} violations: {" | ".join(severity_parts)}'
