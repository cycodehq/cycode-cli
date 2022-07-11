from click.testing import CliRunner
from cli.user_settings.user_settings_commands import set_credentials


def test_set_credentials_no_exist_credentials_in_file(mocker):
    # Arrange
    client_id_user_input = "new client id"
    client_secret_user_input = "new client secret"
    mocker.patch('cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
                 return_value=(None, None))

    # side effect - multiple return values, each item in the list represent return of a call
    mocker.patch('click.prompt', side_effect=[client_id_user_input, client_secret_user_input])
    mocked_update_credentials = mocker.patch(
        'cli.user_settings.credentials_manager.CredentialsManager.update_credentials_file')
    click = CliRunner()

    # Act
    click.invoke(set_credentials)

    # Assert
    mocked_update_credentials.assert_called_once_with(client_id_user_input, client_secret_user_input)


def test_set_credentials_update_current_credentials_in_file(mocker):
    # Arrange
    client_id_user_input = "new client id"
    client_secret_user_input = "new client secret"
    mocker.patch('cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
                 return_value=('client id file', 'client secret file'))

    # side effect - multiple return values, each item in the list represent return of a call
    mocker.patch('click.prompt', side_effect=[client_id_user_input, client_secret_user_input])
    mocked_update_credentials = mocker.patch(
        'cli.user_settings.credentials_manager.CredentialsManager.update_credentials_file')
    click = CliRunner()

    # Act
    click.invoke(set_credentials)

    # Assert
    mocked_update_credentials.assert_called_once_with(client_id_user_input, client_secret_user_input)


def test_set_credentials_update_only_client_id(mocker):
    # Arrange
    client_id_user_input = "new client id"
    current_client_id = 'client secret file'
    mocker.patch('cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
                 return_value=('client id file', 'client secret file'))

    # side effect - multiple return values, each item in the list represent return of a call
    mocker.patch('click.prompt', side_effect=[client_id_user_input, ''])
    mocked_update_credentials = mocker.patch(
        'cli.user_settings.credentials_manager.CredentialsManager.update_credentials_file')
    click = CliRunner()

    # Act
    click.invoke(set_credentials)

    # Assert
    mocked_update_credentials.assert_called_once_with(client_id_user_input, current_client_id)


def test_set_credentials_update_only_client_secret(mocker):
    # Arrange
    client_secret_user_input = "new client secret"
    current_client_id = 'client secret file'
    mocker.patch('cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
                 return_value=(current_client_id, 'client secret file'))

    # side effect - multiple return values, each item in the list represent return of a call
    mocker.patch('click.prompt', side_effect=['', client_secret_user_input])
    mocked_update_credentials = mocker.patch(
        'cli.user_settings.credentials_manager.CredentialsManager.update_credentials_file')
    click = CliRunner()

    # Act
    click.invoke(set_credentials)

    # Assert
    mocked_update_credentials.assert_called_once_with(current_client_id, client_secret_user_input)


def test_set_credentials_should_not_update_file(mocker):
    # Arrange
    client_id_user_input = ""
    client_secret_user_input = ""
    mocker.patch('cli.user_settings.credentials_manager.CredentialsManager.get_credentials_from_file',
                 return_value=('client id file', 'client secret file'))

    # side effect - multiple return values, each item in the list represent return of a call
    mocker.patch('click.prompt', side_effect=[client_id_user_input, client_secret_user_input])
    mocked_update_credentials = mocker.patch(
        'cli.user_settings.credentials_manager.CredentialsManager.update_credentials_file')
    click = CliRunner()

    # Act
    click.invoke(set_credentials)

    # Assert
    assert not mocked_update_credentials.called

