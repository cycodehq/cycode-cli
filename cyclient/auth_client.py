import requests.exceptions
from requests import Response
from typing import Optional
from .cycode_client import CycodeClient
from . import models
from cli.exceptions.custom_exceptions import CycodeError


class AuthClient:
    AUTH_CONTROLLER_PATH = 'api/v1/device-auth'

    def __init__(self):
        self.cycode_client = CycodeClient()

    def start_session(self, code_challenge: str):
        path = f"{self.AUTH_CONTROLLER_PATH}/start"
        body = {'code_challenge': code_challenge}
        try:
            response = self.cycode_client.post(url_path=path, body=body)
            return self.parse_start_session_response(response)
        except requests.exceptions.Timeout as e:
            raise CycodeError(504, e.response.text)
        except requests.exceptions.HTTPError as e:
            raise CycodeError(e.response.status_code, e.response.text)

    def get_api_token(self, session_id: str, code_verifier: str) -> Optional[models.ApiTokenGenerationPollingResponse]:
        path = f"{self.AUTH_CONTROLLER_PATH}/token"
        body = {'session_id': session_id, 'code_verifier': code_verifier}
        try:
            response = self.cycode_client.post(url_path=path, body=body)
            return self.parse_api_token_polling_response(response)
        except requests.exceptions.HTTPError as e:
            return self.parse_api_token_polling_response(e.response)
        except Exception as e:
            return None

    @staticmethod
    def parse_start_session_response(response: Response) -> models.AuthenticationSession:
        return models.AuthenticationSessionSchema().load(response.json())

    @staticmethod
    def parse_api_token_polling_response(response: Response) -> Optional[models.ApiTokenGenerationPollingResponse]:
        try:
            return models.ApiTokenGenerationPollingResponseSchema().load(response.json())
        except Exception as e:
            return None
