import click
import pytest
import typer

from cycode.cli.apps.scan.scan_command import scan_command_result_callback
from cycode.cli.consts import ISSUE_DETECTED_STATUS_CODE, NO_ISSUES_STATUS_CODE, SCAN_ERROR_STATUS_CODE


def _make_ctx(**obj_overrides: object) -> click.Context:
    obj = {
        'soft_fail': False,
        'did_fail': False,
        'issue_detected': False,
        'stop_on_error': False,
    }
    obj.update(obj_overrides)
    ctx = click.Context(click.Command('scan'))
    ctx.obj = obj
    return ctx


def _invoke_result_callback(ctx: click.Context) -> int:
    with pytest.raises(typer.Exit) as exc_info:
        with ctx:
            scan_command_result_callback()
    return exc_info.value.exit_code


class TestScanCommandResultCallback:
    def test_no_issues_no_errors_exits_zero(self) -> None:
        assert _invoke_result_callback(_make_ctx()) == NO_ISSUES_STATUS_CODE

    def test_issue_detected_exits_one(self) -> None:
        assert _invoke_result_callback(_make_ctx(issue_detected=True)) == ISSUE_DETECTED_STATUS_CODE

    def test_did_fail_without_stop_on_error_exits_one(self) -> None:
        assert _invoke_result_callback(_make_ctx(did_fail=True)) == ISSUE_DETECTED_STATUS_CODE

    def test_did_fail_with_stop_on_error_exits_two(self) -> None:
        assert _invoke_result_callback(_make_ctx(did_fail=True, stop_on_error=True)) == SCAN_ERROR_STATUS_CODE

    def test_issue_detected_with_stop_on_error_exits_one(self) -> None:
        # stop_on_error only affects the error code path, not violations
        assert _invoke_result_callback(_make_ctx(issue_detected=True, stop_on_error=True)) == ISSUE_DETECTED_STATUS_CODE

    def test_soft_fail_overrides_violations(self) -> None:
        assert _invoke_result_callback(_make_ctx(soft_fail=True, issue_detected=True)) == NO_ISSUES_STATUS_CODE

    def test_soft_fail_overrides_stop_on_error(self) -> None:
        assert _invoke_result_callback(_make_ctx(soft_fail=True, did_fail=True, stop_on_error=True)) == NO_ISSUES_STATUS_CODE
