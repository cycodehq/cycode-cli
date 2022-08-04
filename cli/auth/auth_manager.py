import webbrowser
from requests import Request
from cli.utils.string_utils import generate_random_string, hash_string_to_sha256
from cli.user_settings.configuration_manager import ConfigurationManager
from cli.user_settings.credentials_manager import CredentialsManager
from cyclient.auth_client import AuthClient
from cyclient.models import ApiToken


class AuthManager:

    CODE_VERIFIER_LENGTH = 101
    POLLING_WAIT_INTERVAL_IN_SECONDS = 3
    POLLING_TIMEOUT_IN_SECONDS = 180

    configuration_manager: ConfigurationManager
    credentials_manager: CredentialsManager
    auth_client: AuthClient

    def __init__(self):
        self.configuration_manager = ConfigurationManager()
        self.credentials_manager = CredentialsManager()
        self.auth_client = AuthClient()

    def authenticate(self):
        code_challenge, code_verifier = self._generate_pkce_code_pair()
        session_id = self.start_session(code_challenge)
        self.redirect_to_login_page(code_challenge, session_id)

    def start_session(self, code_challenge: str):
        return self.auth_client.start_session(code_challenge)

    def redirect_to_login_page(self, code_challenge: str, session_id: str):
        login_url = self._build_login_url(code_challenge, session_id)
        webbrowser.open(login_url)

    def get_api_token(self) -> ApiToken:
        return

    def get_api_token_polling(self):
        return

    def save_api_token(self, api_token: ApiToken):
        self.credentials_manager.update_credentials_file(api_token.client_id, api_token.secret)

    def _build_login_url(self, code_challenge: str, session_id: str):
        app_url = self.configuration_manager.get_cycode_app_url()
        login_url = f'{app_url}/account/login'
        query_params = {
            'source': 'cycode_cli',
            'code_challenge': code_challenge,
            'session_id': session_id
        }
        request = Request(url=login_url, params=query_params)
        return request.url

    def _generate_pkce_code_pair(self) -> (str, str):
        code_verifier = generate_random_string(self.CODE_VERIFIER_LENGTH)
        code_challenge = hash_string_to_sha256(code_verifier)
        return code_challenge, code_verifier


    # def get_api_token(self):
    #
    # def wait_until(self, predicate, timeout_at=30, poll_every=1):
    #     try:
    #         polling.poll(predicate, poll_every, timeout=timeout_at)
    #     except polling.TimeoutException:
    #         raise PyDriverTimeoutException('Timed out after {} seconds waiting for {} to be true. '
    #                                        'The predicate was polled every {} seconds.'.format(timeout_at, predicate,
    #                                                                                            poll_every))