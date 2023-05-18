from requests import Response, request, exceptions

from cycode import __version__
from . import config
from cycode.cli.exceptions.custom_exceptions import NetworkError, HttpUnauthorizedError


class CycodeClientBase:

    MANDATORY_HEADERS: dict = {
        'User-Agent': f'cycode-cli_{__version__}',
    }

    def __init__(self, api_url: str):
        self.timeout = config.timeout
        self.api_url = api_url

    def post(
            self,
            url_path: str,
            body: dict = None,
            headers: dict = None,
            **kwargs
    ) -> Response:
        return self._execute(method='post', endpoint=url_path, json=body, headers=headers, **kwargs)

    def put(
            self,
            url_path: str,
            body: dict = None,
            headers: dict = None,
            **kwargs
    ) -> Response:
        return self._execute(method='put', endpoint=url_path, json=body, headers=headers, **kwargs)

    def get(
            self,
            url_path: str,
            headers: dict = None,
            **kwargs
    ) -> Response:
        return self._execute(method='get', endpoint=url_path, headers=headers, **kwargs)

    def _execute(
            self,
            method: str,
            endpoint: str,
            headers: dict = None,
            **kwargs
    ) -> Response:
        url = self.build_full_url(self.api_url, endpoint)

        try:
            response = request(
                method=method, url=url, timeout=self.timeout, headers=self.get_request_headers(headers), **kwargs
            )

            response.raise_for_status()
            return response
        except Exception as e:
            self._handle_exception(e)

    def get_request_headers(self, additional_headers: dict = None) -> dict:
        if additional_headers is None:
            return self.MANDATORY_HEADERS.copy()
        return {**self.MANDATORY_HEADERS, **additional_headers}

    def build_full_url(self, url: str, endpoint: str) -> str:
        return f'{url}/{endpoint}'

    def _handle_exception(self, e: Exception):
        if isinstance(e, exceptions.Timeout):
            raise NetworkError(504, 'Timeout Error', e.response)
        elif isinstance(e, exceptions.HTTPError):
            self._handle_http_exception(e)
        elif isinstance(e, exceptions.ConnectionError):
            raise NetworkError(502, 'Connection Error', e.response)
        else:
            raise e

    @staticmethod
    def _handle_http_exception(e: exceptions.HTTPError):
        if e.response.status_code == 401:
            raise HttpUnauthorizedError(e.response.text, e.response)

        raise NetworkError(e.response.status_code, e.response.text, e.response)
