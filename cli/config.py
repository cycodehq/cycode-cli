import os

from cli.consts import DEV_MODE_ENV_VAR_NAME
from cli.utils.yaml_utils import read_file
from cli.user_settings.configuration_manager import ConfigurationManager

relative_path = os.path.dirname(__file__)
config_file_path = os.path.join(relative_path, 'config.yaml')
config = read_file(config_file_path)
configuration_manager = ConfigurationManager()
DEFAULT_CONFIGURATION = {
    DEV_MODE_ENV_VAR_NAME: 'False'
}
configuration = dict(DEFAULT_CONFIGURATION, **os.environ)

# env vars
CYCODE_CLIENT_ID_ENV_VAR_NAME = 'CYCODE_CLIENT_ID'
CYCODE_CLIENT_SECRET_ENV_VAR_NAME = 'CYCODE_CLIENT_SECRET'


def _get_val_as_bool(key, default=''):
    val = configuration.get(key, default)
    return val.lower() in ('true', '1')


dev_mode = _get_val_as_bool(DEV_MODE_ENV_VAR_NAME)
