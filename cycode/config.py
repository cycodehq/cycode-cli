import logging
import os
from typing import Optional
from urllib.parse import urlparse

from cycode.cli import consts
from cycode.cyclient import config_dev

DEFAULT_CONFIGURATION = {
    consts.TIMEOUT_ENV_VAR_NAME: 300,
    consts.LOGGING_LEVEL_ENV_VAR_NAME: logging.INFO,
    config_dev.DEV_MODE_ENV_VAR_NAME: 'false',
}

configuration = dict(DEFAULT_CONFIGURATION, **os.environ)


def get_val_as_string(key: str) -> str:
    return configuration.get(key)


def get_val_as_bool(key: str, default: bool = False) -> bool:
    if key not in configuration:
        return default

    return configuration[key].lower() in {'true', '1', 'yes', 'y', 'on', 'enabled'}


def get_val_as_int(key: str) -> Optional[int]:
    val = configuration.get(key)
    if not val:
        return None

    try:
        return int(val)
    except ValueError:
        return None


def is_valid_url(url: str) -> bool:
    try:
        parsed_url = urlparse(url)
        return all([parsed_url.scheme, parsed_url.netloc])
    except ValueError:
        return False
