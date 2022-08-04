from requests import Session, Request
import webbrowser
from cli.utils.string_utils import generate_random_string, hash_string_to_sha256
from cli.user_settings.configuration_manager import ConfigurationManager


class AuthManager:

    CODE_VERIFIER_LENGTH = 101

    def __init__(self):
        self.configuration_manager = ConfigurationManager()

    def generate_pkce_code_pair(self) -> (str, str):
        code_verifier = generate_random_string(self.CODE_VERIFIER_LENGTH)
        code_challenge = hash_string_to_sha256(code_verifier)
        return code_challenge, code_verifier

    def redirect_to_login_page(self):


    def build_login_url(self):
        app_url = self.configuration_manager.
        request = Request(url=)