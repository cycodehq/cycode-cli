from requests import Response, request
from cyclient import config, __version__


class CycodeClient:

    MANDATORY_HEADERS: dict = {
        "User-Agent": f'cycode-cli_{__version__}',
    }

    def __init__(self):
        self.timeout = config.timeout
        self.api_url = config.cycode_api_url

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

        response = request(
            method=method, url=url, timeout=self.timeout, headers=self.get_request_headers(headers), **kwargs
        )
        response.raise_for_status()
        return response

    def get_request_headers(self, additional_headers: dict = None):
        if additional_headers is None:
            return self.MANDATORY_HEADERS
        return {**self.MANDATORY_HEADERS, **additional_headers}

