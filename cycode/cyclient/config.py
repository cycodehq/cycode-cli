from cycode.cli import consts
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.config import get_val_as_bool, get_val_as_int, get_val_as_string, is_valid_url
from cycode.cyclient import config_dev
from cycode.cyclient.logger import logger

configuration_manager = ConfigurationManager()

cycode_api_url = configuration_manager.get_cycode_api_url()
if not is_valid_url(cycode_api_url):
    logger.warning(
        'Invalid Cycode API URL: %s, using default value (%s)', cycode_api_url, consts.DEFAULT_CYCODE_API_URL
    )
    cycode_api_url = consts.DEFAULT_CYCODE_API_URL


cycode_app_url = configuration_manager.get_cycode_app_url()
if not is_valid_url(cycode_app_url):
    logger.warning(
        'Invalid Cycode APP URL: %s, using default value (%s)', cycode_app_url, consts.DEFAULT_CYCODE_APP_URL
    )
    cycode_app_url = consts.DEFAULT_CYCODE_APP_URL


def _is_on_premise_installation(cycode_domain: str) -> bool:
    return not cycode_api_url.endswith(cycode_domain)


on_premise_installation = _is_on_premise_installation(consts.DEFAULT_CYCODE_DOMAIN)

timeout = get_val_as_int(consts.CYCODE_CLI_REQUEST_TIMEOUT_ENV_VAR_NAME)
if not timeout:
    timeout = get_val_as_int(consts.TIMEOUT_ENV_VAR_NAME)

dev_mode = get_val_as_bool(config_dev.DEV_MODE_ENV_VAR_NAME)
dev_tenant_id = get_val_as_string(config_dev.DEV_TENANT_ID_ENV_VAR_NAME)
