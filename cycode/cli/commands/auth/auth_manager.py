import time
import webbrowser
from typing import TYPE_CHECKING, Tuple

from requests import Request

from cycode.cli.exceptions.custom_exceptions import AuthProcessError
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cli.utils.string_utils import generate_random_string, hash_string_to_sha256
from cycode.cyclient import logger
from cycode.cyclient.auth_client import AuthClient
from cycode.cyclient.models import ApiTokenGenerationPollingResponse

if TYPE_CHECKING:
    from cycode.cyclient.models import ApiToken


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
        logger.debug('generating pkce code pair')
        code_challenge, code_verifier = self._generate_pkce_code_pair()

        logger.debug('starting authentication session')
        session_id = self.start_session(code_challenge)
        logger.debug('authentication session created, %s', {'session_id': session_id})

        logger.debug('opening browser and redirecting to cycode login page')
        self.redirect_to_login_page(code_challenge, session_id)

        logger.debug('starting get api token process')
        api_token = self.get_api_token(session_id, code_verifier)

        logger.debug('saving get api token')
        self.save_api_token(api_token)

    def start_session(self, code_challenge: str) -> str:
        auth_session = self.auth_client.start_session(code_challenge)
        return auth_session.session_id

    def redirect_to_login_page(self, code_challenge: str, session_id: str) -> None:
        login_url = self._build_login_url(code_challenge, session_id)
        webbrowser.open(login_url)

    def get_api_token(self, session_id: str, code_verifier: str) -> 'ApiToken':
        api_token = self.get_api_token_polling(session_id, code_verifier)
        if api_token is None:
            raise AuthProcessError('getting api token is completed, but the token is missing')
        return api_token

    def get_api_token_polling(self, session_id: str, code_verifier: str) -> 'ApiToken':
        end_polling_time = time.time() + self.POLLING_TIMEOUT_IN_SECONDS
        while time.time() < end_polling_time:
            logger.debug('trying to get api token...')
            api_token_polling_response = self.auth_client.get_api_token(session_id, code_verifier)
            if self._is_api_token_process_completed(api_token_polling_response):
                logger.debug('get api token process completed')
                return api_token_polling_response.api_token
            if self._is_api_token_process_failed(api_token_polling_response):
                logger.debug('get api token process failed')
                raise AuthProcessError('error during getting api token')
            time.sleep(self.POLLING_WAIT_INTERVAL_IN_SECONDS)

        raise AuthProcessError('session expired')

    def save_api_token(self, api_token: 'ApiToken') -> None:
        self.credentials_manager.update_credentials_file(api_token.client_id, api_token.secret)

    def _build_login_url(self, code_challenge: str, session_id: str) -> str:
        app_url = self.configuration_manager.get_cycode_app_url()
        login_url = f'{app_url}/account/sign-in'
        query_params = {'source': 'cycode_cli', 'code_challenge': code_challenge, 'session_id': session_id}
        # TODO(MarshalX). Use auth_client instead and don't depend on "requests" lib here
        request = Request(url=login_url, params=query_params)
        return request.prepare().url

    def _generate_pkce_code_pair(self) -> Tuple[str, str]:
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
