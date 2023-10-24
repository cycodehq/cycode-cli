from typing import Optional

import click

from cycode.cli import config, consts
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cli.utils.string_utils import obfuscate_text

_URLS_UPDATED_SUCCESSFULLY_MESSAGE = 'Successfully configured Cycode URLs! Saved to: {filename}'
_URLS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE = (
    'Note that the URLs (APP and API) that already exist in environment variables '
    f'({consts.CYCODE_API_URL_ENV_VAR_NAME} and {consts.CYCODE_APP_URL_ENV_VAR_NAME}) '
    'take precedent over these URLs; either update or remove the environment variables.'
)
_CREDENTIALS_UPDATED_SUCCESSFULLY_MESSAGE = 'Successfully configured CLI credentials! Saved to: {filename}'
_CREDENTIALS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE = (
    'Note that the credentials that already exist in environment variables '
    f'({config.CYCODE_CLIENT_ID_ENV_VAR_NAME} and {config.CYCODE_CLIENT_SECRET_ENV_VAR_NAME}) '
    'take precedent over these credentials; either update or remove the environment variables.'
)
_CREDENTIALS_MANAGER = CredentialsManager()
_CONFIGURATION_MANAGER = ConfigurationManager()


@click.command(short_help='Initial command to configure your CLI client authentication.')
def configure_command() -> None:
    """Configure your CLI client authentication manually."""
    global_config_manager = _CONFIGURATION_MANAGER.global_config_file_manager

    current_api_url = global_config_manager.get_api_url()
    current_app_url = global_config_manager.get_app_url()
    api_url = _get_api_url_input(current_api_url)
    app_url = _get_app_url_input(current_app_url)

    config_updated = False
    if _should_update_value(current_api_url, api_url):
        global_config_manager.update_api_base_url(api_url)
        config_updated = True
    if _should_update_value(current_app_url, app_url):
        global_config_manager.update_app_base_url(app_url)
        config_updated = True

    current_client_id, current_client_secret = _CREDENTIALS_MANAGER.get_credentials_from_file()
    client_id = _get_client_id_input(current_client_id)
    client_secret = _get_client_secret_input(current_client_secret)

    credentials_updated = False
    if _should_update_value(current_client_id, client_id) or _should_update_value(current_client_secret, client_secret):
        credentials_updated = True
        _CREDENTIALS_MANAGER.update_credentials_file(client_id, client_secret)

    if config_updated:
        click.echo(_get_urls_update_result_message())
    if credentials_updated:
        click.echo(_get_credentials_update_result_message())


def _get_client_id_input(current_client_id: Optional[str]) -> Optional[str]:
    prompt_text = 'Cycode Client ID'

    prompt_suffix = ' []: '
    if current_client_id:
        prompt_suffix = f' [{obfuscate_text(current_client_id)}]: '

    new_client_id = click.prompt(text=prompt_text, prompt_suffix=prompt_suffix, default='', show_default=False)
    return new_client_id or current_client_id


def _get_client_secret_input(current_client_secret: Optional[str]) -> Optional[str]:
    prompt_text = 'Cycode Client Secret'

    prompt_suffix = ' []: '
    if current_client_secret:
        prompt_suffix = f' [{obfuscate_text(current_client_secret)}]: '

    new_client_secret = click.prompt(text=prompt_text, prompt_suffix=prompt_suffix, default='', show_default=False)
    return new_client_secret or current_client_secret


def _get_app_url_input(current_app_url: Optional[str]) -> str:
    prompt_text = 'Cycode APP URL'

    default = consts.DEFAULT_CYCODE_APP_URL
    if current_app_url:
        default = current_app_url

    return click.prompt(text=prompt_text, default=default, type=click.STRING)


def _get_api_url_input(current_api_url: Optional[str]) -> str:
    prompt_text = 'Cycode API URL'

    default = consts.DEFAULT_CYCODE_API_URL
    if current_api_url:
        default = current_api_url

    return click.prompt(text=prompt_text, default=default, type=click.STRING)


def _get_credentials_update_result_message() -> str:
    success_message = _CREDENTIALS_UPDATED_SUCCESSFULLY_MESSAGE.format(filename=_CREDENTIALS_MANAGER.get_filename())
    if _are_credentials_exist_in_environment_variables():
        return f'{success_message}. {_CREDENTIALS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE}'

    return success_message


def _are_credentials_exist_in_environment_variables() -> bool:
    client_id, client_secret = _CREDENTIALS_MANAGER.get_credentials_from_environment_variables()
    return any([client_id, client_secret])


def _get_urls_update_result_message() -> str:
    success_message = _URLS_UPDATED_SUCCESSFULLY_MESSAGE.format(
        filename=_CONFIGURATION_MANAGER.global_config_file_manager.get_filename()
    )
    if _are_urls_exist_in_environment_variables():
        return f'{success_message}. {_URLS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE}'

    return success_message


def _are_urls_exist_in_environment_variables() -> bool:
    api_url = _CONFIGURATION_MANAGER.get_api_url_from_environment_variables()
    app_url = _CONFIGURATION_MANAGER.get_app_url_from_environment_variables()
    return any([api_url, app_url])


def _should_update_value(
    old_value: Optional[str],
    new_value: Optional[str],
) -> bool:
    if not new_value:
        return False

    return old_value != new_value
