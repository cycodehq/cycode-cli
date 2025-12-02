from typing import Any

from cycode.cli.user_settings.jwt_creator import JwtCreator
from cycode.cyclient.base_token_auth_client import BaseTokenAuthClient


class CycodeOidcBasedClient(BaseTokenAuthClient):
    """Send requests with JWT obtained via OIDC ID token."""

    def __init__(self, client_id: str, id_token: str) -> None:
        self.id_token = id_token
        super().__init__(client_id)

    def _request_new_access_token(self) -> dict[str, Any]:
        auth_response = self.post(
            url_path='api/v1/auth/oidc/api-token',
            body={'client_id': self.client_id, 'id_token': self.id_token},
            without_auth=True,
            hide_response_content_log=True,
        )
        return auth_response.json()

    def _create_jwt_creator(self) -> JwtCreator:
        return JwtCreator.create(self.client_id, self.id_token)
