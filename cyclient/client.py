import arrow
import requests.exceptions
from requests import Response, request
from threading import Lock
from cyclient import config
from cli.exceptions.custom_exceptions import CycodeError, HttpUnauthorizedError


class CycodeClient:

    def __init__(self, client_id: str, client_secret: str):
        """
        :param client_secret: the api token to added to the requests
        :param api_url: the cycode api url
        """
        self.client_secret = client_secret
        self.client_id = client_id
        self.timeout = config.timeout

        self.api_url = config.cycode_api_url

        self._api_token = None
        self._expires_in = None

        self.lock = Lock()

    @property
    def api_token(self) -> str:
        with self.lock:
            self.refresh_api_token_if_needed()
            return self._api_token

    def refresh_api_token_if_needed(self) -> None:
        if self._api_token is None or self._expires_in is None or arrow.utcnow() >= self._expires_in:
            self.refresh_api_token()

    def refresh_api_token(self) -> None:
        try:
            auth_response = requests.post(f"{self.api_url}/api/v1/auth/api-token",
                                          json={
                                              'clientId': self.client_id,
                                              'secret': self.client_secret
                                          })
            auth_response.raise_for_status()
        except requests.exceptions.HTTPError as e:  # 4xx/5xx status codes
            self._handle_http_exception(e)

        auth_response_data = auth_response.json()
        self._api_token = auth_response_data['token']
        self._expires_in = arrow.utcnow().shift(
            seconds=auth_response_data['expires_in'] * 0.8)

    def post(
            self,
            url_path: str,
            body: dict = None,
            headers: dict = None,
            **kwargs
    ) -> Response:
        return self._execute(
            method="post", endpoint=url_path, json=body, headers=headers, **kwargs)

    def put(
            self,
            url_path: str,
            body: dict = None,
            headers: dict = None,
            **kwargs
    ) -> Response:
        return self._execute(
            method="put", endpoint=url_path, json=body, headers=headers, **kwargs)

    def get(
            self,
            url_path: str,
            headers: dict = None,
            **kwargs
    ) -> Response:
        return self._execute(method="get", endpoint=url_path, headers=headers, **kwargs)

    def _execute(
            self,
            method: str,
            endpoint: str,
            headers: dict = None,
            **kwargs
    ) -> Response:

        url = f"{self.api_url}/{endpoint}"

        try:
            response = request(
                method=method, url=url, timeout=self.timeout, headers=self.get_request_headers(headers), **kwargs
            )
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            raise CycodeError(504, "Timeout Error")
        except requests.exceptions.HTTPError as e:  # 4xx/5xx status codes
            self._handle_http_exception(e)

    def get_request_headers(self, additional_headers: dict = None):
        headers = {
            "User-Agent": "cycode-cli"
        }

        if additional_headers is None:
            return headers
        return {**headers, **additional_headers}

    def _handle_http_exception(self, e: requests.exceptions.HTTPError):
        if e.response.status_code == 401:
            raise HttpUnauthorizedError(e.response.text)
        else:
            raise CycodeError(e.response.status_code, e.response.text)
