import logging
import os
import sys
from urllib.parse import urlparse
from cli.user_settings.configuration_manager import ConfigurationManager
from cli.consts import DEFAULT_CYCODE_API_URL, TIMEOUT_ENV_VAR_NAME, LOGGING_LEVEL_ENV_VAR_NAME, DEV_MODE_ENV_VAR_NAME, \
    BATCH_SIZE_ENV_VAR_NAME, VERBOSE_ENV_VAR_NAME


# set io encoding (for windows)
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')


# logs
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("werkzeug").setLevel(logging.WARNING)
logging.getLogger("schedule").setLevel(logging.WARNING)
logging.getLogger("kubernetes").setLevel(logging.WARNING)
logging.getLogger("binaryornot").setLevel(logging.WARNING)
logging.getLogger("chardet").setLevel(logging.WARNING)
logging.getLogger("git.cmd").setLevel(logging.WARNING)
logging.getLogger("git.util").setLevel(logging.WARNING)

# configs
DEFAULT_CONFIGURATION = {
    TIMEOUT_ENV_VAR_NAME: 60,
    LOGGING_LEVEL_ENV_VAR_NAME: logging.INFO,
    DEV_MODE_ENV_VAR_NAME: 'False',
    BATCH_SIZE_ENV_VAR_NAME: 20
}

configuration = dict(DEFAULT_CONFIGURATION, **os.environ)


def get_logger(logger_name=None):
    logger = logging.getLogger(logger_name)
    level = _get_val_as_string(LOGGING_LEVEL_ENV_VAR_NAME)
    level = level if level in logging._nameToLevel.keys() else int(level)
    logger.setLevel(level)

    return logger


def _get_val_as_string(key):
    return configuration.get(key)


def _get_val_as_bool(key, default=''):
    val = configuration.get(key, default)
    return val.lower() in ('true', '1')


def _get_val_as_int(key):
    val = configuration.get(key)
    return int(val) if val is not None else None


logger = get_logger("cycode cli")

configuration_manager = ConfigurationManager()

base_url = configuration_manager.get_base_url()
try:
    urlparse(base_url)
except ValueError as e:
    logger.warning(f'Invalid cycode api url: {base_url}, using default value', e)
    base_url = DEFAULT_CYCODE_API_URL

timeout = _get_val_as_int(TIMEOUT_ENV_VAR_NAME)
dev_mode = _get_val_as_bool(DEV_MODE_ENV_VAR_NAME)
batch_size = _get_val_as_int(BATCH_SIZE_ENV_VAR_NAME)
verbose = _get_val_as_bool(VERBOSE_ENV_VAR_NAME)