from typing import Optional

from cycode.cli.apps.configure.consts import CONFIGURATION_MANAGER, CREDENTIALS_MANAGER
from cycode.cli.apps.configure.messages import get_credentials_update_result_message, get_urls_update_result_message
from cycode.cli.apps.configure.prompts import (
    get_api_url_input,
    get_app_url_input,
    get_client_id_input,
    get_client_secret_input,
)
from cycode.cli.console import console
from cycode.cli.utils.sentry import add_breadcrumb


def _should_update_value(
    old_value: Optional[str],
    new_value: Optional[str],
) -> bool:
    if not new_value:
        return False

    return old_value != new_value


def configure_command() -> None:
    """:gear: [bold cyan]Configure Cycode CLI settings.[/]

    This command allows you to configure various aspects of the Cycode CLI.

    Configuration options:
    * API URL: The base URL for Cycode's API (for on-premise or EU installations)
    * APP URL: The base URL for Cycode's web application (for on-premise or EU installations)
    * Client ID: Your Cycode client ID for authentication
    * Client Secret: Your Cycode client secret for authentication

    Example usage:
    * `cycode configure`: Start interactive configuration
    * `cycode configure --help`: View configuration options
    """
    add_breadcrumb('configure')

    global_config_manager = CONFIGURATION_MANAGER.global_config_file_manager

    current_api_url = global_config_manager.get_api_url()
    current_app_url = global_config_manager.get_app_url()
    api_url = get_api_url_input(current_api_url)
    app_url = get_app_url_input(current_app_url)

    config_updated = False
    if _should_update_value(current_api_url, api_url):
        global_config_manager.update_api_base_url(api_url)
        config_updated = True
    if _should_update_value(current_app_url, app_url):
        global_config_manager.update_app_base_url(app_url)
        config_updated = True

    current_client_id, current_client_secret = CREDENTIALS_MANAGER.get_credentials_from_file()
    client_id = get_client_id_input(current_client_id)
    client_secret = get_client_secret_input(current_client_secret)

    credentials_updated = False
    if _should_update_value(current_client_id, client_id) or _should_update_value(current_client_secret, client_secret):
        credentials_updated = True
        CREDENTIALS_MANAGER.update_credentials(client_id, client_secret)

    if config_updated:
        console.print(get_urls_update_result_message())
    if credentials_updated:
        console.print(get_credentials_update_result_message())
