import logging
import os
import sys
from typing import NamedTuple, Optional, Set, Union
from urllib.parse import urlparse

from cycode.cli import consts
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cyclient import config_dev


def _set_io_encodings() -> None:
    # set io encoding (for Windows)
    sys.stdout.reconfigure(encoding='UTF-8')
    sys.stderr.reconfigure(encoding='UTF-8')


_set_io_encodings()

# logs
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('schedule').setLevel(logging.WARNING)
logging.getLogger('kubernetes').setLevel(logging.WARNING)
logging.getLogger('binaryornot').setLevel(logging.WARNING)
logging.getLogger('chardet').setLevel(logging.WARNING)
logging.getLogger('git.cmd').setLevel(logging.WARNING)
logging.getLogger('git.util').setLevel(logging.WARNING)

# configs
DEFAULT_CONFIGURATION = {
    consts.TIMEOUT_ENV_VAR_NAME: 300,
    consts.LOGGING_LEVEL_ENV_VAR_NAME: logging.INFO,
    config_dev.DEV_MODE_ENV_VAR_NAME: 'false',
}

configuration = dict(DEFAULT_CONFIGURATION, **os.environ)


class CreatedLogger(NamedTuple):
    logger: logging.Logger
    control_level_in_runtime: bool


_CREATED_LOGGERS: Set[CreatedLogger] = set()


def get_logger_level() -> Optional[Union[int, str]]:
    config_level = get_val_as_string(consts.LOGGING_LEVEL_ENV_VAR_NAME)
    return logging.getLevelName(config_level)


def get_logger(logger_name: Optional[str] = None, control_level_in_runtime: bool = True) -> logging.Logger:
    new_logger = logging.getLogger(logger_name)
    new_logger.setLevel(get_logger_level())

    _CREATED_LOGGERS.add(CreatedLogger(logger=new_logger, control_level_in_runtime=control_level_in_runtime))

    return new_logger


def set_logging_level(level: int) -> None:
    for created_logger in _CREATED_LOGGERS:
        if created_logger.control_level_in_runtime:
            created_logger.logger.setLevel(level)


def get_val_as_string(key: str) -> str:
    return configuration.get(key)


def get_val_as_bool(key: str, default: str = '') -> bool:
    val = configuration.get(key, default)
    return val.lower() in {'true', '1'}


def get_val_as_int(key: str) -> Optional[int]:
    val = configuration.get(key)
    if val:
        return int(val)

    return None


def is_valid_url(url: str) -> bool:
    try:
        parsed_url = urlparse(url)
        return all([parsed_url.scheme, parsed_url.netloc])
    except ValueError:
        return False


logger = get_logger('cycode cli')
configuration_manager = ConfigurationManager()

cycode_api_url = configuration_manager.get_cycode_api_url()
if not is_valid_url(cycode_api_url):
    logger.warning(
        'Invalid Cycode API URL: %s, using default value (%s)', cycode_api_url, consts.DEFAULT_CYCODE_API_URL
    )
    cycode_api_url = consts.DEFAULT_CYCODE_API_URL


def _is_on_premise_installation(cycode_domain: str) -> bool:
    return not cycode_api_url.endswith(cycode_domain)


on_premise_installation = _is_on_premise_installation(consts.DEFAULT_CYCODE_DOMAIN)

timeout = get_val_as_int(consts.CYCODE_CLI_REQUEST_TIMEOUT_ENV_VAR_NAME)
if not timeout:
    timeout = get_val_as_int(consts.TIMEOUT_ENV_VAR_NAME)

dev_mode = get_val_as_bool(config_dev.DEV_MODE_ENV_VAR_NAME)
dev_tenant_id = get_val_as_string(config_dev.DEV_TENANT_ID_ENV_VAR_NAME)
