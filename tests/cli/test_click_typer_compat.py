"""Guards the seam between Typer and the Click APIs the CLI uses directly.

The CLI raises ``click.ClickException``, mounts a raw ``click.Group`` (``platform``)
into the Typer app, and relies on Typer rendering both. Typer releases that vendor
their own copy of Click (0.26+) silently break these paths, so cover them end to end.
"""

from unittest.mock import patch

import click
from typer.testing import CliRunner

from cycode.cli.app import app
from tests.conftest import CLI_ENV_VARS

_BASE_ARGS = ['--no-update-notifier']


def _invoke(*args: str) -> 'click.testing.Result':
    return CliRunner().invoke(app, [*_BASE_ARGS, *args], env=CLI_ENV_VARS)


def test_click_exception_is_rendered_as_error_not_traceback() -> None:
    result = _invoke('ignore')

    assert result.exit_code == 1
    assert 'Ignore by type is missing' in result.output
    assert 'Traceback' not in result.output
    assert isinstance(result.exception, SystemExit)


def _fake_platform_groups(*_: object) -> list[tuple[click.Group, str]]:
    group = click.Group(name='tools', help='Fake tools group')

    @group.command(name='ping', help='Fake ping command')
    def ping() -> None:
        click.echo('pong')

    return [(group, 'tools')]


def test_platform_click_group_is_mounted_and_invocable() -> None:
    with patch('cycode.cli.apps.api.api_command.build_api_command_groups', side_effect=_fake_platform_groups):
        help_result = _invoke('platform', '--help')
        run_result = _invoke('platform', 'tools', 'ping')

    assert help_result.exit_code == 0, help_result.output
    assert 'tools' in help_result.output

    assert run_result.exit_code == 0, run_result.output
    assert 'pong' in run_result.output


def test_misspelled_command_suggests_once() -> None:
    result = _invoke('scna')

    assert result.exit_code == 2
    assert result.output.count("Did you mean 'scan'?") == 1


def test_group_without_args_shows_help_with_usage_exit_code() -> None:
    result = _invoke('scan')

    assert result.exit_code == 2
    assert 'Usage' in result.output
