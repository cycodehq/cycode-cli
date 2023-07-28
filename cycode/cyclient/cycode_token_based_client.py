from threading import Lock
from typing import Optional

import arrow

from .cycode_client import CycodeClient


class CycodeTokenBasedClient(CycodeClient):
    """Send requests with api token"""

    def __init__(self, client_id: str, client_secret: str) -> None:
        super().__init__()
        self.client_secret = client_secret
        self.client_id = client_id

        self._api_token = None
        self._expires_in = None

        self.lock = Lock()

    @property
    def api_token(self) -> str:
        # TODO(MarshalX): This property performs HTTP request to refresh the token. This must be the method.
        with self.lock:
            self.refresh_api_token_if_needed()
            return self._api_token

    def refresh_api_token_if_needed(self) -> None:
        if self._api_token is None or self._expires_in is None or arrow.utcnow() >= self._expires_in:
            self.refresh_api_token()

    def refresh_api_token(self) -> None:
        auth_response = self.post(
            url_path='api/v1/auth/api-token',
            body={'clientId': self.client_id, 'secret': self.client_secret},
            without_auth=True,
            hide_response_content_log=True,
        )
        auth_response_data = auth_response.json()

        self._api_token = auth_response_data['token']
        self._expires_in = arrow.utcnow().shift(seconds=auth_response_data['expires_in'] * 0.8)

    def get_request_headers(self, additional_headers: Optional[dict] = None, without_auth: bool = False) -> dict:
        headers = super().get_request_headers(additional_headers=additional_headers)

        if not without_auth:
            headers = self._add_auth_header(headers)

        return headers

    def _add_auth_header(self, headers: dict) -> dict:
        headers['Authorization'] = f'Bearer {self.api_token}'
        return headers
