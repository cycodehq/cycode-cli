from typing import TYPE_CHECKING

import click
import pytest
from click import ClickException
from git import InvalidGitRepositoryError
from requests import Response

from cycode.cli.exceptions import custom_exceptions
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture()
def ctx() -> click.Context:
    return click.Context(click.Command('path'), obj={'verbose': False, 'output': 'text'})


@pytest.mark.parametrize(
    'exception, expected_soft_fail',
    [
        (custom_exceptions.NetworkError(400, 'msg', Response()), True),
        (custom_exceptions.ScanAsyncError('msg'), True),
        (custom_exceptions.HttpUnauthorizedError('msg', Response()), True),
        (custom_exceptions.ZipTooLargeError(1000), True),
        (custom_exceptions.TfplanKeyError('msg'), True),
        (InvalidGitRepositoryError(), None),
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
    with ctx, pytest.raises(ClickException):
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

    def mock_secho(msg: str, *_, **__) -> None:
        assert 'Error:' in msg or 'Correlation ID:' in msg

    monkeypatch.setattr(click, 'secho', mock_secho)

    with ctx, pytest.raises(ClickException):
        handle_scan_exception(ctx, ValueError('test'))
