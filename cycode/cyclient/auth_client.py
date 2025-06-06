from typing import Optional

from requests import Request, Response

from cycode.cli.exceptions.custom_exceptions import HttpUnauthorizedError, RequestHttpError
from cycode.cyclient import config, models
from cycode.cyclient.cycode_client import CycodeClient


class AuthClient:
    AUTH_CONTROLLER_PATH = 'api/v1/device-auth'

    def __init__(self) -> None:
        self.cycode_client = CycodeClient()

    @staticmethod
    def build_login_url(code_challenge: str, session_id: str) -> str:
        query_params = {'source': 'cycode_cli', 'code_challenge': code_challenge, 'session_id': session_id}
        return Request(url=f'{config.cycode_app_url}/account/sign-in', params=query_params).prepare().url

    def start_session(self, code_challenge: str) -> models.AuthenticationSession:
        path = f'{self.AUTH_CONTROLLER_PATH}/start'
        body = {'code_challenge': code_challenge}
        response = self.cycode_client.post(url_path=path, body=body)
        return self.parse_start_session_response(response)

    def get_api_token(self, session_id: str, code_verifier: str) -> Optional[models.ApiTokenGenerationPollingResponse]:
        path = f'{self.AUTH_CONTROLLER_PATH}/token'
        body = {'session_id': session_id, 'code_verifier': code_verifier}
        try:
            response = self.cycode_client.post(url_path=path, body=body, hide_response_content_log=True)
            return self.parse_api_token_polling_response(response)
        except (RequestHttpError, HttpUnauthorizedError) as e:
            return self.parse_api_token_polling_response(e.response)
        except Exception:
            return None

    @staticmethod
    def parse_start_session_response(response: Response) -> models.AuthenticationSession:
        return models.AuthenticationSessionSchema().load(response.json())

    @staticmethod
    def parse_api_token_polling_response(response: Response) -> Optional[models.ApiTokenGenerationPollingResponse]:
        try:
            return models.ApiTokenGenerationPollingResponseSchema().load(response.json())
        except Exception:
            return None
