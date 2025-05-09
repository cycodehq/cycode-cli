from typing import TYPE_CHECKING, Any

import click
import pytest
import typer
from requests import Response
from rich.traceback import Traceback

from cycode.cli.cli_types import OutputTypeOption
from cycode.cli.console import console_err
from cycode.cli.exceptions import custom_exceptions
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.printers import ConsolePrinter
from cycode.cli.utils.git_proxy import git_proxy

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture
def ctx() -> typer.Context:
    ctx = typer.Context(click.Command('path'), obj={'verbose': False, 'output': OutputTypeOption.TEXT})
    ctx.obj['console_printer'] = ConsolePrinter(ctx)
    return ctx


@pytest.mark.parametrize(
    ('exception', 'expected_soft_fail'),
    [
        (custom_exceptions.RequestHttpError(400, 'msg', Response()), True),
        (custom_exceptions.ScanAsyncError('msg'), True),
        (custom_exceptions.HttpUnauthorizedError('msg', Response()), True),
        (custom_exceptions.ZipTooLargeError(1000), True),
        (custom_exceptions.TfplanKeyError('msg'), True),
        (git_proxy.get_invalid_git_repository_error()(), None),
    ],
)
def test_handle_exception_soft_fail(
    ctx: typer.Context, exception: custom_exceptions.CycodeError, expected_soft_fail: bool
) -> None:
    with ctx:
        handle_scan_exception(ctx, exception)

        assert ctx.obj.get('did_fail') is True
        assert ctx.obj.get('soft_fail') is expected_soft_fail


def test_handle_exception_unhandled_error(ctx: typer.Context) -> None:
    with ctx, pytest.raises(typer.Exit):
        handle_scan_exception(ctx, ValueError('test'))

        assert ctx.obj.get('did_fail') is True
        assert ctx.obj.get('soft_fail') is None


def test_handle_exception_click_error(ctx: typer.Context) -> None:
    with ctx, pytest.raises(click.ClickException):
        handle_scan_exception(ctx, click.ClickException('test'))

        assert ctx.obj.get('did_fail') is True
        assert ctx.obj.get('soft_fail') is None


def test_handle_exception_verbose(monkeypatch: 'MonkeyPatch') -> None:
    ctx = typer.Context(click.Command('path'), obj={'verbose': True, 'output': OutputTypeOption.TEXT})
    ctx.obj['console_printer'] = ConsolePrinter(ctx)

    error_text = 'test'

    def mock_console_print(obj: Any, *_, **__) -> None:
        if isinstance(obj, str):
            assert 'Correlation ID:' in obj
        else:
            assert isinstance(obj, Traceback)
            assert error_text in str(obj.trace)

    monkeypatch.setattr(console_err, 'print', mock_console_print)

    with pytest.raises(typer.Exit):
        handle_scan_exception(ctx, ValueError(error_text))
