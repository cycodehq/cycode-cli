from typing import Any

from cycode.cli.user_settings.jwt_creator import JwtCreator
from cycode.cyclient.base_token_auth_client import BaseTokenAuthClient


class CycodeTokenBasedClient(BaseTokenAuthClient):
    """Send requests with JWT."""

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_secret = client_secret
        super().__init__(client_id)

    def _request_new_access_token(self) -> dict[str, Any]:
        auth_response = self.post(
            url_path='api/v1/auth/api-token',
            body={'clientId': self.client_id, 'secret': self.client_secret},
            without_auth=True,
            hide_response_content_log=True,
        )
        return auth_response.json()

    def _create_jwt_creator(self) -> JwtCreator:
        return JwtCreator.create(self.client_id, self.client_secret)
