import time
import webbrowser
from typing import TYPE_CHECKING

from cycode.cli.exceptions.custom_exceptions import AuthProcessError
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cli.utils.string_utils import generate_random_string, hash_string_to_sha256
from cycode.cyclient.auth_client import AuthClient
from cycode.cyclient.models import ApiTokenGenerationPollingResponse
from cycode.logger import get_logger

if TYPE_CHECKING:
    from cycode.cyclient.models import ApiToken


logger = get_logger('Auth Manager')


class AuthManager:
    CODE_VERIFIER_LENGTH = 101
    POLLING_WAIT_INTERVAL_IN_SECONDS = 3
    POLLING_TIMEOUT_IN_SECONDS = 180
    FAILED_POLLING_STATUS = 'Error'
    COMPLETED_POLLING_STATUS = 'Completed'

    def __init__(self) -> None:
        self.configuration_manager = ConfigurationManager()
        self.credentials_manager = CredentialsManager()
        self.auth_client = AuthClient()

    def authenticate(self) -> None:
        logger.debug('Generating PKCE code pair')
        code_challenge, code_verifier = self._generate_pkce_code_pair()

        logger.debug('Starting authentication session')
        session_id = self.start_session(code_challenge)
        logger.debug('Authentication session created, %s', {'session_id': session_id})

        logger.debug('Opening browser and redirecting to Cycode login page')
        self.redirect_to_login_page(code_challenge, session_id)

        logger.debug('Getting API token')
        api_token = self.get_api_token(session_id, code_verifier)

        logger.debug('Saving API token')
        self.save_api_token(api_token)

    def start_session(self, code_challenge: str) -> str:
        auth_session = self.auth_client.start_session(code_challenge)
        return auth_session.session_id

    def redirect_to_login_page(self, code_challenge: str, session_id: str) -> None:
        login_url = self.auth_client.build_login_url(code_challenge, session_id)
        webbrowser.open(login_url)

    def get_api_token(self, session_id: str, code_verifier: str) -> 'ApiToken':
        api_token = self.get_api_token_polling(session_id, code_verifier)
        if api_token is None:
            raise AuthProcessError('API token pulling is completed, but the token is missing')
        return api_token

    def get_api_token_polling(self, session_id: str, code_verifier: str) -> 'ApiToken':
        end_polling_time = time.time() + self.POLLING_TIMEOUT_IN_SECONDS
        while time.time() < end_polling_time:
            logger.debug('Trying to get API token...')
            api_token_polling_response = self.auth_client.get_api_token(session_id, code_verifier)
            if self._is_api_token_process_completed(api_token_polling_response):
                logger.debug('Got API token process completion response')
                return api_token_polling_response.api_token
            if self._is_api_token_process_failed(api_token_polling_response):
                logger.debug('Got API token process failure response')
                raise AuthProcessError('Error while obtaining API token')
            time.sleep(self.POLLING_WAIT_INTERVAL_IN_SECONDS)

        raise AuthProcessError('Timeout while obtaining API token (session expired)')

    def save_api_token(self, api_token: 'ApiToken') -> None:
        self.credentials_manager.update_credentials(api_token.client_id, api_token.secret)

    def _generate_pkce_code_pair(self) -> tuple[str, str]:
        code_verifier = generate_random_string(self.CODE_VERIFIER_LENGTH)
        code_challenge = hash_string_to_sha256(code_verifier)
        return code_challenge, code_verifier

    def _is_api_token_process_completed(self, api_token_polling_response: ApiTokenGenerationPollingResponse) -> bool:
        return (
            api_token_polling_response is not None
            and api_token_polling_response.status == self.COMPLETED_POLLING_STATUS
        )

    def _is_api_token_process_failed(self, api_token_polling_response: ApiTokenGenerationPollingResponse) -> bool:
        return (
            api_token_polling_response is not None and api_token_polling_response.status == self.FAILED_POLLING_STATUS
        )
