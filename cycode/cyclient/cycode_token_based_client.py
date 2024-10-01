from threading import Lock
from typing import Optional

import arrow
from requests import Response

from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cli.user_settings.jwt_creator import JwtCreator
from cycode.cyclient.cycode_client import CycodeClient

_NGINX_PLAIN_ERRORS = [
    b'Invalid JWT Token',
    b'JWT Token Needed',
    b'JWT Token validation failed',
]


class CycodeTokenBasedClient(CycodeClient):
    """Send requests with JWT."""

    def __init__(self, client_id: str, client_secret: str) -> None:
        super().__init__()
        self.client_secret = client_secret
        self.client_id = client_id

        self._credentials_manager = CredentialsManager()
        # load cached access token
        access_token, expires_in, creator = self._credentials_manager.get_access_token()

        self._access_token = self._expires_in = None
        if creator == JwtCreator.create(client_id, client_secret):
            # we must be sure that cached access token is created using the same client id and client secret.
            # because client id and client secret could be passed via command, via env vars or via config file.
            # we must not use cached access token if client id or client secret was changed.
            self._access_token = access_token
            self._expires_in = arrow.get(expires_in) if expires_in else None

        self._lock = Lock()

    def get_access_token(self) -> str:
        with self._lock:
            self.refresh_access_token_if_needed()
            return self._access_token

    def invalidate_access_token(self, in_storage: bool = False) -> None:
        self._access_token = None
        self._expires_in = None

        if in_storage:
            self._credentials_manager.update_access_token(None, None, None)

    def refresh_access_token_if_needed(self) -> None:
        if self._access_token is None or self._expires_in is None or arrow.utcnow() >= self._expires_in:
            self.refresh_access_token()

    def refresh_access_token(self) -> None:
        auth_response = self.post(
            url_path='api/v1/auth/api-token',
            body={'clientId': self.client_id, 'secret': self.client_secret},
            without_auth=True,
            hide_response_content_log=True,
        )
        auth_response_data = auth_response.json()

        self._access_token = auth_response_data['token']
        self._expires_in = arrow.utcnow().shift(seconds=auth_response_data['expires_in'] * 0.8)

        jwt_creator = JwtCreator.create(self.client_id, self.client_secret)
        self._credentials_manager.update_access_token(self._access_token, self._expires_in.timestamp(), jwt_creator)

    def get_request_headers(self, additional_headers: Optional[dict] = None, without_auth: bool = False) -> dict:
        headers = super().get_request_headers(additional_headers=additional_headers)

        if not without_auth:
            headers = self._add_auth_header(headers)

        return headers

    def _add_auth_header(self, headers: dict) -> dict:
        headers['Authorization'] = f'Bearer {self.get_access_token()}'
        return headers

    def _execute(
        self,
        *args,
        **kwargs,
    ) -> Response:
        response = super()._execute(*args, **kwargs)

        # backend returns 200 and plain text. no way to catch it with .raise_for_status()
        nginx_error_response = any(response.content.startswith(plain_error) for plain_error in _NGINX_PLAIN_ERRORS)
        if response.status_code == 200 and nginx_error_response:
            # if cached token is invalid, try to refresh it and retry the request
            self.refresh_access_token()
            response = super()._execute(*args, **kwargs)

        return response
