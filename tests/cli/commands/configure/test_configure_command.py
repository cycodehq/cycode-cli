from typing import TYPE_CHECKING

from typer.testing import CliRunner

from cycode.cli.app import app

if TYPE_CHECKING:
    from pytest_mock import MockerFixture


def test_configure_command_no_exist_values_in_file(mocker: 'MockerFixture') -> None:
    # Arrange
    app_url_user_input = 'new app url'
    api_url_user_input = 'new api url'
    client_id_user_input = 'new client id'
    client_secret_user_input = 'new client secret'
    id_token_user_input = 'new id token'

    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
        return_value=(None, None),
    )
    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_oidc_credentials_from_file',
        return_value=(None, None),
    )
    mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.get_api_url',
        return_value=None,
    )
    mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.get_app_url',
        return_value=None,
    )

    # side effect - multiple return values, each item in the list represents return of a call
    mocker.patch(
        'typer.prompt',
        side_effect=[api_url_user_input, app_url_user_input, client_id_user_input, client_secret_user_input, id_token_user_input],
    )

    mocked_update_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_credentials'
    )
    mocked_update_oidc_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_oidc_credentials'
    )
    mocked_update_api_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_api_base_url'
    )
    mocked_update_app_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_app_base_url'
    )

    # Act
    CliRunner().invoke(app, ['configure'])

    # Assert
    mocked_update_credentials.assert_called_once_with(client_id_user_input, client_secret_user_input)
    mocked_update_oidc_credentials.assert_called_once_with(client_id_user_input, id_token_user_input)
    mocked_update_api_base_url.assert_called_once_with(api_url_user_input)
    mocked_update_app_base_url.assert_called_once_with(app_url_user_input)


def test_configure_command_update_current_configs_in_files(mocker: 'MockerFixture') -> None:
    # Arrange
    app_url_user_input = 'new app url'
    api_url_user_input = 'new api url'
    client_id_user_input = 'new client id'
    client_secret_user_input = 'new client secret'
    id_token_user_input = 'new id token'

    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
        return_value=('client id file', 'client secret file'),
    )
    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_oidc_credentials_from_file',
        return_value=('client id file', 'id token file'),
    )
    mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.get_api_url',
        return_value='api url file',
    )
    mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.get_app_url',
        return_value='app url file',
    )

    # side effect - multiple return values, each item in the list represents return of a call
    mocker.patch(
        'typer.prompt',
        side_effect=[api_url_user_input, app_url_user_input, client_id_user_input, client_secret_user_input, id_token_user_input],
    )

    mocked_update_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_credentials'
    )
    mocked_update_api_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_api_base_url'
    )
    mocked_update_app_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_app_base_url'
    )
    mocker_update_oidc_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_oidc_credentials'
    )

    # Act
    CliRunner().invoke(app, ['configure'])

    # Assert
    mocked_update_credentials.assert_called_once_with(client_id_user_input, client_secret_user_input)
    mocker_update_oidc_credentials.assert_called_once_with(client_id_user_input, id_token_user_input)
    mocked_update_api_base_url.assert_called_once_with(api_url_user_input)
    mocked_update_app_base_url.assert_called_once_with(app_url_user_input)


def test_set_credentials_update_only_client_id(mocker: 'MockerFixture') -> None:
    # Arrange
    client_id_user_input = 'new client id'
    current_client_id = 'client secret file'
    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
        return_value=('client id file', 'client secret file'),
    )

    # side effect - multiple return values, each item in the list represents return of a call
    mocker.patch('typer.prompt', side_effect=['', '', client_id_user_input, '', ''])
    mocked_update_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_credentials'
    )

    # Act
    CliRunner().invoke(app, ['configure'])

    # Assert
    mocked_update_credentials.assert_called_once_with(client_id_user_input, current_client_id)


def test_configure_command_update_only_client_secret(mocker: 'MockerFixture') -> None:
    # Arrange
    client_secret_user_input = 'new client secret'
    current_client_id = 'client secret file'

    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
        return_value=(current_client_id, 'client secret file'),
    )

    # side effect - multiple return values, each item in the list represents return of a call
    mocker.patch('typer.prompt', side_effect=['', '', '', client_secret_user_input, ''])
    mocked_update_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_credentials'
    )

    # Act
    CliRunner().invoke(app, ['configure'])

    # Assert
    mocked_update_credentials.assert_called_once_with(current_client_id, client_secret_user_input)


def test_configure_command_update_only_api_url(mocker: 'MockerFixture') -> None:
    # Arrange
    api_url_user_input = 'new api url'
    current_api_url = 'api url'

    mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.get_api_url',
        return_value=current_api_url,
    )

    # side effect - multiple return values, each item in the list represents return of a call
    mocker.patch('typer.prompt', side_effect=[api_url_user_input, '', '', '', ''])
    mocked_update_api_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_api_base_url'
    )

    # Act
    CliRunner().invoke(app, ['configure'])

    # Assert
    mocked_update_api_base_url.assert_called_once_with(api_url_user_input)


def test_configure_command_update_only_id_token(mocker: 'MockerFixture') -> None:
    # Arrange
    current_client_id = 'client id file'
    current_id_token = 'old id token'
    new_id_token = 'new id token'

    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
        return_value=(current_client_id, 'client secret file'),
    )
    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_oidc_credentials_from_file',
        return_value=(current_client_id, current_id_token),
    )

    mocker.patch('typer.prompt', side_effect=['', '', '', '', new_id_token])

    mocked_update_oidc_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_oidc_credentials'
    )

    # Act
    CliRunner().invoke(app, ['configure'])

    # Assert
    mocked_update_oidc_credentials.assert_called_once_with(current_client_id, new_id_token)


def test_configure_command_should_not_update_credentials(mocker: 'MockerFixture') -> None:
    # Arrange
    client_id_user_input = ''
    client_secret_user_input = ''

    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
        return_value=('client id file', 'client secret file'),
    )

    # side effect - multiple return values, each item in the list represents return of a call
    mocker.patch('typer.prompt', side_effect=['', '', client_id_user_input, client_secret_user_input, ''])
    mocked_update_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_credentials'
    )

    # Act
    CliRunner().invoke(app, ['configure'])

    # Assert
    assert not mocked_update_credentials.called


def test_configure_command_should_not_update_config_file(mocker: 'MockerFixture') -> None:
    # Arrange
    app_url_user_input = ''
    api_url_user_input = ''

    mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.get_api_url',
        return_value='api url file',
    )
    mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.get_app_url',
        return_value='app url file',
    )

    # side effect - multiple return values, each item in the list represents return of a call
    mocker.patch('typer.prompt', side_effect=[api_url_user_input, app_url_user_input, '', '', ''])
    mocked_update_api_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_api_base_url'
    )
    mocked_update_app_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_app_base_url'
    )

    # Act
    CliRunner().invoke(app, ['configure'])

    # Assert
    assert not mocked_update_api_base_url.called
    assert not mocked_update_app_base_url.called


def test_configure_command_should_not_update_oidc_credentials(mocker: 'MockerFixture') -> None:
    # Arrange
    current_client_id = 'client id file'
    current_client_secret = 'client secret file'
    current_id_token = 'old id token'

    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
        return_value=(current_client_id, current_client_secret),
    )
    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_oidc_credentials_from_file',
        return_value=(current_client_id, current_id_token),
    )
    mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.get_api_url',
        return_value='api url file',
    )
    mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.get_app_url',
        return_value='app url file',
    )

    mocker.patch('typer.prompt', side_effect=['', '', '', '', ''])

    mocked_update_oidc_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_oidc_credentials'
    )

    # Act
    CliRunner().invoke(app, ['configure'])

    # Assert
    mocked_update_oidc_credentials.assert_not_called()
