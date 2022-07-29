from mock import Mock
from cli.user_settings.configuration_manager import ConfigurationManager
from cli.consts import DEFAULT_CYCODE_API_URL

"""
we check for base url in the three places, in the following order:
1. environment vars
2. local file config
3. global file config
"""
ENV_VARS_BASE_URL_VALUE = 'url_from_env_vars'
LOCAL_CONFIG_FILE_BASE_URL_VALUE = 'url_from_local_config_file'
GLOBAL_CONFIG_BASE_URL_VALUE = 'url_from_global_config_file'


def test_get_base_url_from_environment_variable(mocker):
    # Arrange
    configuration_manager = _configure_mocks(mocker, ENV_VARS_BASE_URL_VALUE, LOCAL_CONFIG_FILE_BASE_URL_VALUE,
                                             GLOBAL_CONFIG_BASE_URL_VALUE)

    # Act
    result = configuration_manager.get_base_url()

    # Assert
    assert result == ENV_VARS_BASE_URL_VALUE


def test_get_base_url_from_local_config(mocker):
    # Arrange
    configuration_manager = _configure_mocks(mocker, None, LOCAL_CONFIG_FILE_BASE_URL_VALUE,
                                             GLOBAL_CONFIG_BASE_URL_VALUE)

    # Act
    result = configuration_manager.get_base_url()

    # Assert
    assert result == LOCAL_CONFIG_FILE_BASE_URL_VALUE


def test_get_base_url_from_global_config(mocker):
    # Arrange
    configuration_manager = _configure_mocks(mocker, None, None, GLOBAL_CONFIG_BASE_URL_VALUE)

    # Act
    result = configuration_manager.get_base_url()

    # Assert
    assert result == GLOBAL_CONFIG_BASE_URL_VALUE


def test_get_base_url_not_configured(mocker):
    # Arrange
    configuration_manager = _configure_mocks(mocker, None, None, None)

    # Act
    result = configuration_manager.get_base_url()

    # Assert
    assert result == DEFAULT_CYCODE_API_URL


def _configure_mocks(mocker,
                     expected_env_var_base_url,
                     expected_local_config_file_base_url,
                     expected_global_config_file_base_url):
    mocker.patch.object(ConfigurationManager, 'get_base_url_from_environment_variables',
                        return_value=expected_env_var_base_url)
    configuration_manager = ConfigurationManager()
    configuration_manager.local_config_file_manager = Mock()
    configuration_manager.local_config_file_manager.get_base_url.return_value = expected_local_config_file_base_url
    configuration_manager.global_config_file_manager = Mock()
    configuration_manager.global_config_file_manager.get_base_url.return_value = expected_global_config_file_base_url

    return configuration_manager
