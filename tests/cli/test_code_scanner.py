import click
import pytest
from click import ClickException
from git import InvalidGitRepositoryError
from requests import Response

from cycode.cli.code_scanner import _handle_exception  # noqa
from cycode.cli.exceptions import custom_exceptions


@pytest.fixture()
def ctx():
    return click.Context(click.Command('path'), obj={'verbose': False, 'output': 'text'})


@pytest.mark.parametrize('exception, expected_soft_fail', [
    (custom_exceptions.NetworkError(400, 'msg', Response()), True),
    (custom_exceptions.ScanAsyncError('msg'), True),
    (custom_exceptions.HttpUnauthorizedError('msg', Response()), True),
    (custom_exceptions.ZipTooLargeError(1000), True),
    (InvalidGitRepositoryError(), None),
])
def test_handle_exception_soft_fail(
        ctx: click.Context, exception: custom_exceptions.CycodeError, expected_soft_fail: bool):
    with ctx:
        _handle_exception(ctx, exception)

        assert ctx.obj.get('did_fail') is True
        assert ctx.obj.get('soft_fail') is expected_soft_fail


def test_handle_exception_unhandled_error(ctx: click.Context):
    with ctx:
        with pytest.raises(ClickException):
            _handle_exception(ctx, ValueError('test'))

            assert ctx.obj.get('did_fail') is True
            assert ctx.obj.get('soft_fail') is None


def test_handle_exception_click_error(ctx: click.Context):
    with ctx:
        with pytest.raises(ClickException):
            _handle_exception(ctx, click.ClickException('test'))

            assert ctx.obj.get('did_fail') is True
            assert ctx.obj.get('soft_fail') is None


def test_handle_exception_verbose(monkeypatch):
    ctx = click.Context(click.Command('path'), obj={'verbose': True, 'output': 'text'})

    def mock_secho(msg, *_, **__):
        assert 'Error:' in msg

    monkeypatch.setattr(click, 'secho', mock_secho)

    with ctx:
        with pytest.raises(ClickException):
            _handle_exception(ctx, ValueError('test'))
