from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from cycode import __version__
from cycode.cli.app import app
from cycode.cli.cli_types import OutputTypeOption
from cycode.cli.utils.version_checker import VersionChecker
from tests.conftest import CLI_ENV_VARS

_NEW_LATEST_VERSION = '999.0.0'  # Simulate a newer version available
_UPDATE_MESSAGE_PART = 'new release of cycode cli is available'


@patch.object(VersionChecker, 'check_for_update')
def test_version_check_with_json_output(mock_check_update: patch) -> None:
    # When output is JSON, version check should be skipped
    mock_check_update.return_value = _NEW_LATEST_VERSION

    args = ['--output', OutputTypeOption.JSON, 'version']
    result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

    # Version check message should not be present in JSON output
    assert _UPDATE_MESSAGE_PART not in result.output.lower()
    mock_check_update.assert_not_called()


@pytest.fixture
def mock_auth_info() -> 'patch':
    # Mock the authorization info to avoid API calls
    with patch('cycode.cli.apps.auth.auth_common.get_authorization_info', return_value=None) as mock:
        yield mock


@pytest.mark.parametrize('command', ['version', 'status'])
@patch.object(VersionChecker, 'check_for_update')
def test_version_check_for_special_commands(mock_check_update: patch, mock_auth_info: patch, command: str) -> None:
    # Version and status commands should always check the version without cache
    mock_check_update.return_value = _NEW_LATEST_VERSION

    result = CliRunner().invoke(app, [command], env=CLI_ENV_VARS)

    # Version information should be present in output
    assert _UPDATE_MESSAGE_PART in result.output.lower()
    # Version check must be called without a cache
    mock_check_update.assert_called_once_with(__version__, False)


@patch.object(VersionChecker, 'check_for_update')
def test_version_check_with_text_output(mock_check_update: patch) -> None:
    # Regular commands with text output should check the version using cache
    mock_check_update.return_value = _NEW_LATEST_VERSION

    args = ['version']
    result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

    # Version check message should be present in JSON output
    assert _UPDATE_MESSAGE_PART in result.output.lower()


@patch.object(VersionChecker, 'check_for_update')
def test_version_check_disabled(mock_check_update: patch) -> None:
    # When --no-update-notifier is used, version check should be skipped
    mock_check_update.return_value = _NEW_LATEST_VERSION

    args = ['--no-update-notifier', 'version']
    result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

    # Version check message should not be present
    assert _UPDATE_MESSAGE_PART not in result.output.lower()
    mock_check_update.assert_not_called()
