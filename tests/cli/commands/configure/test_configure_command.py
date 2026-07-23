import os
from typing import TYPE_CHECKING

import pytest
import yaml
from click.testing import CliRunner
from typer.main import get_command

from cycode.cli.app import app
from cycode.cli.apps.configure.consts import CONFIGURATION_MANAGER, CREDENTIALS_MANAGER
from cycode.cli.user_settings.config_file_manager import ConfigFileManager
from cycode.cli.user_settings.credentials_manager import CredentialsManager

if TYPE_CHECKING:
    from pytest_mock import MockerFixture

# Built eagerly on the real filesystem; building it under pyfakefs breaks typer's
# pathlib.Path parameter introspection.
_click_app = get_command(app)

# `cycode configure` reads/writes the real ~/.cycode files; run every test on pyfakefs
# so file access never reaches the developer's machine.
pytestmark = pytest.mark.usefixtures('fs')

_CURRENT_CREDENTIALS = {
    CredentialsManager.CLIENT_ID_FIELD_NAME: 'current client id',
    CredentialsManager.CLIENT_SECRET_FIELD_NAME: 'current client secret',
    CredentialsManager.ID_TOKEN_FIELD_NAME: 'current id token',
}
_CURRENT_CONFIG = {
    ConfigFileManager.ENVIRONMENT_SECTION_NAME: {
        ConfigFileManager.API_URL_FIELD_NAME: 'current api url',
        ConfigFileManager.APP_URL_FIELD_NAME: 'current app url',
    }
}


def _credentials_filename() -> str:
    return CREDENTIALS_MANAGER.get_filename()


def _config_filename() -> str:
    return CONFIGURATION_MANAGER.global_config_file_manager.get_filename()


def _seed_yaml(filename: str, content: dict) -> None:
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', encoding='UTF-8') as file:
        yaml.safe_dump(content, file)


def _read_yaml(filename: str) -> dict:
    with open(filename, encoding='UTF-8') as file:
        return yaml.safe_load(file)


def _run_configure(mocker: 'MockerFixture', prompt_answers: list[str]) -> None:
    # Prompt order: api url, app url, client id, client secret, id token
    mocker.patch('typer.prompt', side_effect=prompt_answers)
    result = CliRunner().invoke(_click_app, ['configure'])
    assert result.exit_code == 0


def test_configure_command_no_exist_values_in_file(mocker: 'MockerFixture') -> None:
    _run_configure(mocker, ['new api url', 'new app url', 'new client id', 'new client secret', 'new id token'])

    assert _read_yaml(_credentials_filename()) == {
        CredentialsManager.CLIENT_ID_FIELD_NAME: 'new client id',
        CredentialsManager.CLIENT_SECRET_FIELD_NAME: 'new client secret',
        CredentialsManager.ID_TOKEN_FIELD_NAME: 'new id token',
    }
    assert _read_yaml(_config_filename()) == {
        ConfigFileManager.ENVIRONMENT_SECTION_NAME: {
            ConfigFileManager.API_URL_FIELD_NAME: 'new api url',
            ConfigFileManager.APP_URL_FIELD_NAME: 'new app url',
        }
    }


def test_configure_command_update_current_configs_in_files(mocker: 'MockerFixture') -> None:
    _seed_yaml(_credentials_filename(), _CURRENT_CREDENTIALS)
    _seed_yaml(_config_filename(), _CURRENT_CONFIG)

    _run_configure(mocker, ['new api url', 'new app url', 'new client id', 'new client secret', 'new id token'])

    assert _read_yaml(_credentials_filename()) == {
        CredentialsManager.CLIENT_ID_FIELD_NAME: 'new client id',
        CredentialsManager.CLIENT_SECRET_FIELD_NAME: 'new client secret',
        CredentialsManager.ID_TOKEN_FIELD_NAME: 'new id token',
    }
    assert _read_yaml(_config_filename()) == {
        ConfigFileManager.ENVIRONMENT_SECTION_NAME: {
            ConfigFileManager.API_URL_FIELD_NAME: 'new api url',
            ConfigFileManager.APP_URL_FIELD_NAME: 'new app url',
        }
    }


def test_set_credentials_update_only_client_id(mocker: 'MockerFixture') -> None:
    _seed_yaml(_credentials_filename(), _CURRENT_CREDENTIALS)

    _run_configure(mocker, ['', '', 'new client id', '', ''])

    # Client id is replaced in both the token and OIDC credential pairs; everything else is kept
    assert _read_yaml(_credentials_filename()) == {
        **_CURRENT_CREDENTIALS,
        CredentialsManager.CLIENT_ID_FIELD_NAME: 'new client id',
    }
    assert not os.path.exists(_config_filename())


def test_configure_command_update_only_client_secret(mocker: 'MockerFixture') -> None:
    _seed_yaml(_credentials_filename(), _CURRENT_CREDENTIALS)

    _run_configure(mocker, ['', '', '', 'new client secret', ''])

    assert _read_yaml(_credentials_filename()) == {
        **_CURRENT_CREDENTIALS,
        CredentialsManager.CLIENT_SECRET_FIELD_NAME: 'new client secret',
    }


def test_configure_command_update_only_api_url(mocker: 'MockerFixture') -> None:
    _seed_yaml(_config_filename(), _CURRENT_CONFIG)

    _run_configure(mocker, ['new api url', '', '', '', ''])

    assert _read_yaml(_config_filename()) == {
        ConfigFileManager.ENVIRONMENT_SECTION_NAME: {
            ConfigFileManager.API_URL_FIELD_NAME: 'new api url',
            ConfigFileManager.APP_URL_FIELD_NAME: 'current app url',
        }
    }
    assert not os.path.exists(_credentials_filename())


def test_configure_command_update_only_id_token(mocker: 'MockerFixture') -> None:
    _seed_yaml(_credentials_filename(), _CURRENT_CREDENTIALS)

    _run_configure(mocker, ['', '', '', '', 'new id token'])

    assert _read_yaml(_credentials_filename()) == {
        **_CURRENT_CREDENTIALS,
        CredentialsManager.ID_TOKEN_FIELD_NAME: 'new id token',
    }


def test_configure_command_should_not_update_credentials(mocker: 'MockerFixture') -> None:
    _seed_yaml(_credentials_filename(), _CURRENT_CREDENTIALS)

    _run_configure(mocker, ['', '', '', '', ''])

    assert _read_yaml(_credentials_filename()) == _CURRENT_CREDENTIALS


def test_configure_command_should_not_update_config_file(mocker: 'MockerFixture') -> None:
    _seed_yaml(_config_filename(), _CURRENT_CONFIG)

    _run_configure(mocker, ['', '', '', '', ''])

    assert _read_yaml(_config_filename()) == _CURRENT_CONFIG


def test_configure_command_should_not_update_oidc_credentials(mocker: 'MockerFixture') -> None:
    _seed_yaml(_credentials_filename(), _CURRENT_CREDENTIALS)

    # Re-entering the same client id must not rewrite anything
    _run_configure(mocker, ['', '', 'current client id', '', ''])

    assert _read_yaml(_credentials_filename()) == _CURRENT_CREDENTIALS
