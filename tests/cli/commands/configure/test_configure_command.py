from typing import TYPE_CHECKING

from click.testing import CliRunner

from cycode.cli.commands.configure.configure_command import configure_command

if TYPE_CHECKING:
    from pytest_mock import MockerFixture


def test_configure_command_no_exist_values_in_file(mocker: 'MockerFixture') -> None:
    # Arrange
    app_url_user_input = 'new app url'
    api_url_user_input = 'new api url'
    client_id_user_input = 'new client id'
    client_secret_user_input = 'new client secret'

    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
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
        'click.prompt',
        side_effect=[api_url_user_input, app_url_user_input, client_id_user_input, client_secret_user_input],
    )

    mocked_update_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_credentials_file'
    )
    mocked_update_api_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_api_base_url'
    )
    mocked_update_app_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_app_base_url'
    )

    # Act
    CliRunner().invoke(configure_command)

    # Assert
    mocked_update_credentials.assert_called_once_with(client_id_user_input, client_secret_user_input)
    mocked_update_api_base_url.assert_called_once_with(api_url_user_input)
    mocked_update_app_base_url.assert_called_once_with(app_url_user_input)


def test_configure_command_update_current_configs_in_files(mocker: 'MockerFixture') -> None:
    # Arrange
    app_url_user_input = 'new app url'
    api_url_user_input = 'new api url'
    client_id_user_input = 'new client id'
    client_secret_user_input = 'new client secret'

    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
        return_value=('client id file', 'client secret file'),
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
        'click.prompt',
        side_effect=[api_url_user_input, app_url_user_input, client_id_user_input, client_secret_user_input],
    )

    mocked_update_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_credentials_file'
    )
    mocked_update_api_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_api_base_url'
    )
    mocked_update_app_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_app_base_url'
    )

    # Act
    CliRunner().invoke(configure_command)

    # Assert
    mocked_update_credentials.assert_called_once_with(client_id_user_input, client_secret_user_input)
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
    mocker.patch('click.prompt', side_effect=['', '', client_id_user_input, ''])
    mocked_update_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_credentials_file'
    )

    # Act
    CliRunner().invoke(configure_command)

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
    mocker.patch('click.prompt', side_effect=['', '', '', client_secret_user_input])
    mocked_update_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_credentials_file'
    )

    # Act
    CliRunner().invoke(configure_command)

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
    mocker.patch('click.prompt', side_effect=[api_url_user_input, '', '', ''])
    mocked_update_api_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_api_base_url'
    )

    # Act
    CliRunner().invoke(configure_command)

    # Assert
    mocked_update_api_base_url.assert_called_once_with(api_url_user_input)


def test_configure_command_should_not_update_credentials_file(mocker: 'MockerFixture') -> None:
    # Arrange
    client_id_user_input = ''
    client_secret_user_input = ''

    mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
        return_value=('client id file', 'client secret file'),
    )

    # side effect - multiple return values, each item in the list represents return of a call
    mocker.patch('click.prompt', side_effect=['', '', client_id_user_input, client_secret_user_input])
    mocked_update_credentials = mocker.patch(
        'cycode.cli.user_settings.credentials_manager.CredentialsManager.update_credentials_file'
    )

    # Act
    CliRunner().invoke(configure_command)

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
    mocker.patch('click.prompt', side_effect=[api_url_user_input, app_url_user_input, '', ''])
    mocked_update_api_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_api_base_url'
    )
    mocked_update_app_base_url = mocker.patch(
        'cycode.cli.user_settings.config_file_manager.ConfigFileManager.update_app_base_url'
    )

    # Act
    CliRunner().invoke(configure_command)

    # Assert
    assert not mocked_update_api_base_url.called
    assert not mocked_update_app_base_url.called
