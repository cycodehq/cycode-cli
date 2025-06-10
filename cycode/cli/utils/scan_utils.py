import os
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import typer

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult


def set_issue_detected(ctx: typer.Context, issue_detected: bool) -> None:
    ctx.obj['issue_detected'] = issue_detected


def set_issue_detected_by_scan_results(ctx: typer.Context, scan_results: list['LocalScanResult']) -> None:
    set_issue_detected(ctx, any(scan_result.issue_detected for scan_result in scan_results))


def is_scan_failed(ctx: typer.Context) -> bool:
    did_fail = ctx.obj.get('did_fail')
    issue_detected = ctx.obj.get('issue_detected')
    return did_fail or issue_detected


def generate_unique_scan_id() -> UUID:
    if 'PYTEST_TEST_UNIQUE_ID' in os.environ:
        return UUID(os.environ['PYTEST_TEST_UNIQUE_ID'])

    return uuid4()
