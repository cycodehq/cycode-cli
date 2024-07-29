from typing import TYPE_CHECKING

import click
import pytest
from click import ClickException
from requests import Response

from cycode.cli.exceptions import custom_exceptions
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.utils.git_proxy import git_proxy

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture()
def ctx() -> click.Context:
    return click.Context(click.Command('path'), obj={'verbose': False, 'output': 'text'})


@pytest.mark.parametrize(
    'exception, expected_soft_fail',
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
    ctx: click.Context, exception: custom_exceptions.CycodeError, expected_soft_fail: bool
) -> None:
    with ctx:
        handle_scan_exception(ctx, exception)

        assert ctx.obj.get('did_fail') is True
        assert ctx.obj.get('soft_fail') is expected_soft_fail


def test_handle_exception_unhandled_error(ctx: click.Context) -> None:
    with ctx, pytest.raises(SystemExit):
        handle_scan_exception(ctx, ValueError('test'))

        assert ctx.obj.get('did_fail') is True
        assert ctx.obj.get('soft_fail') is None


def test_handle_exception_click_error(ctx: click.Context) -> None:
    with ctx, pytest.raises(ClickException):
        handle_scan_exception(ctx, click.ClickException('test'))

        assert ctx.obj.get('did_fail') is True
        assert ctx.obj.get('soft_fail') is None


def test_handle_exception_verbose(monkeypatch: 'MonkeyPatch') -> None:
    ctx = click.Context(click.Command('path'), obj={'verbose': True, 'output': 'text'})

    error_text = 'test'

    def mock_secho(msg: str, *_, **__) -> None:
        assert error_text in msg or 'Correlation ID:' in msg

    monkeypatch.setattr(click, 'secho', mock_secho)

    with pytest.raises(SystemExit):
        handle_scan_exception(ctx, ValueError(error_text))
