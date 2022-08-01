from requests import Response

from .client import CycodeClient
from . import models


class AuthClient(CycodeClient):
    AUTH_CONTROLLER_PATH = 'api/v1/device-auth'

    def __init__(self, client_id: str = None, client_secret: str = None):
        super().__init__(client_id, client_secret)

    def start_session(self, code_challenge: str):
        path = f"/{self.AUTH_CONTROLLER_PATH}/start"
        body = {'code_challenge': code_challenge}
        response = self.post(url_path=path, body=body)
        return self.parse_start_session_response(response)

    def get_api_token(self, session_id: str, code_verifier: str):
        path = f"/{self.AUTH_CONTROLLER_PATH}/token"
        body = {'session_id': session_id, 'code_verifier': code_verifier}
        response = self.post(url_path=path, body=body)
        return self.parse_start_session_response(response)

    @staticmethod
    def parse_start_session_response(response: Response) -> models.ScanResult:
        return models.AuthenticationSessionSchema().load(response.json())

    @staticmethod
    def parse_api_token_polling_response(response: Response):
        return models.ApiTokenGenerationPollingResponseSchema().load(response.json())
