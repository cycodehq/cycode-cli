from cycode.cli import config, consts
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.user_settings.credentials_manager import CredentialsManager

URLS_UPDATED_SUCCESSFULLY_MESSAGE = 'Successfully configured Cycode URLs! Saved to: {filename}'
URLS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE = (
    'Note that the URLs (APP and API) that already exist in environment variables '
    f'({consts.CYCODE_API_URL_ENV_VAR_NAME} and {consts.CYCODE_APP_URL_ENV_VAR_NAME}) '
    'take precedent over these URLs; either update or remove the environment variables.'
)
CREDENTIALS_UPDATED_SUCCESSFULLY_MESSAGE = 'Successfully configured CLI credentials! Saved to: {filename}'
CREDENTIALS_ARE_SET_IN_ENVIRONMENT_VARIABLES_MESSAGE = (
    'Note that the credentials that already exist in environment variables '
    f'({config.CYCODE_CLIENT_ID_ENV_VAR_NAME} and {config.CYCODE_CLIENT_SECRET_ENV_VAR_NAME}) '
    'take precedent over these credentials; either update or remove the environment variables.'
)

CREDENTIALS_MANAGER = CredentialsManager()
CONFIGURATION_MANAGER = ConfigurationManager()
