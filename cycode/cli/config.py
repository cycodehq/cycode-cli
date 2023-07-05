import os

from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.utils.yaml_utils import read_file

relative_path = os.path.dirname(__file__)
config_file_path = os.path.join(relative_path, 'config.yaml')
config = read_file(config_file_path)
configuration_manager = ConfigurationManager()

# env vars
CYCODE_CLIENT_ID_ENV_VAR_NAME = 'CYCODE_CLIENT_ID'
CYCODE_CLIENT_SECRET_ENV_VAR_NAME = 'CYCODE_CLIENT_SECRET'  # noqa: S105
