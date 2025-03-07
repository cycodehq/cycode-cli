from cycode.cli.apps.configure.consts import (
    CONFIGURATION_MANAGER,
    CREDENTIALS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE,
    CREDENTIALS_MANAGER,
    CREDENTIALS_UPDATED_SUCCESSFULLY_MESSAGE,
    URLS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE,
    URLS_UPDATED_SUCCESSFULLY_MESSAGE,
)


def _are_credentials_exist_in_environment_variables() -> bool:
    client_id, client_secret = CREDENTIALS_MANAGER.get_credentials_from_environment_variables()
    return any([client_id, client_secret])


def get_credentials_update_result_message() -> str:
    success_message = CREDENTIALS_UPDATED_SUCCESSFULLY_MESSAGE.format(filename=CREDENTIALS_MANAGER.get_filename())
    if _are_credentials_exist_in_environment_variables():
        return f'{success_message}. {CREDENTIALS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE}'

    return success_message


def _are_urls_exist_in_environment_variables() -> bool:
    api_url = CONFIGURATION_MANAGER.get_api_url_from_environment_variables()
    app_url = CONFIGURATION_MANAGER.get_app_url_from_environment_variables()
    return any([api_url, app_url])


def get_urls_update_result_message() -> str:
    success_message = URLS_UPDATED_SUCCESSFULLY_MESSAGE.format(
        filename=CONFIGURATION_MANAGER.global_config_file_manager.get_filename()
    )
    if _are_urls_exist_in_environment_variables():
        return f'{success_message}. {URLS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE}'

    return success_message
