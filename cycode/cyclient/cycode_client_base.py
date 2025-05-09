import os
import platform
import ssl
from typing import TYPE_CHECKING, Callable, ClassVar, Optional

import requests
from requests import Response, exceptions
from requests.adapters import HTTPAdapter
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_random_exponential

from cycode.cli.exceptions.custom_exceptions import (
    HttpUnauthorizedError,
    RequestConnectionError,
    RequestError,
    RequestHttpError,
    RequestSslError,
    RequestTimeoutError,
)
from cycode.cyclient import config
from cycode.cyclient.headers import get_cli_user_agent, get_correlation_id
from cycode.cyclient.logger import logger

if TYPE_CHECKING:
    from tenacity import RetryCallState


class SystemStorageSslContext(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs) -> None:
        default_context = ssl.create_default_context()
        default_context.load_default_certs()
        kwargs['ssl_context'] = default_context
        return super().init_poolmanager(*args, **kwargs)

    def cert_verify(self, *args, **kwargs) -> None:
        super().cert_verify(*args, **kwargs)
        conn = kwargs['conn'] if 'conn' in kwargs else args[0]
        conn.ca_certs = None


def _get_request_function() -> Callable:
    if os.environ.get('REQUESTS_CA_BUNDLE') or os.environ.get('CURL_CA_BUNDLE'):
        return requests.request

    if platform.system() != 'Windows':
        return requests.request

    session = requests.Session()
    session.mount('https://', SystemStorageSslContext())
    return session.request


_REQUEST_ERRORS_TO_RETRY = (
    RequestTimeoutError,
    RequestConnectionError,
    exceptions.ChunkedEncodingError,
    exceptions.ContentDecodingError,
)
_RETRY_MAX_ATTEMPTS = 3
_RETRY_STOP_STRATEGY = stop_after_attempt(_RETRY_MAX_ATTEMPTS)
_RETRY_WAIT_STRATEGY = wait_random_exponential(multiplier=1, min=2, max=10)


def _retry_before_sleep(retry_state: 'RetryCallState') -> None:
    exception_name = 'None'
    if retry_state.outcome.failed:
        exception = retry_state.outcome.exception()
        exception_name = f'{exception.__class__.__name__}'

    logger.debug(
        'Retrying request after error: %s. Attempt %s of %s. Upcoming sleep: %s',
        exception_name,
        retry_state.attempt_number,
        _RETRY_MAX_ATTEMPTS,
        retry_state.upcoming_sleep,
    )


def _should_retry_exception(exception: BaseException) -> bool:
    if 'PYTEST_CURRENT_TEST' in os.environ:
        # We are running under pytest, don't retry
        return False

    # Don't retry client errors (400, 401, etc.)
    if isinstance(exception, RequestHttpError):
        return not exception.status_code < 500

    is_request_error = isinstance(exception, _REQUEST_ERRORS_TO_RETRY)
    is_server_error = isinstance(exception, RequestHttpError) and exception.status_code >= 500

    return is_request_error or is_server_error


class CycodeClientBase:
    MANDATORY_HEADERS: ClassVar[dict[str, str]] = {
        'User-Agent': get_cli_user_agent(),
        'X-Correlation-Id': get_correlation_id(),
    }

    def __init__(self, api_url: str) -> None:
        self.timeout = config.timeout
        self.api_url = api_url

    @staticmethod
    def reset_user_agent() -> None:
        CycodeClientBase.MANDATORY_HEADERS['User-Agent'] = get_cli_user_agent()

    @staticmethod
    def enrich_user_agent(user_agent_suffix: str) -> None:
        CycodeClientBase.MANDATORY_HEADERS['User-Agent'] += f' {user_agent_suffix}'

    def post(self, url_path: str, body: Optional[dict] = None, headers: Optional[dict] = None, **kwargs) -> Response:
        return self._execute(method='post', endpoint=url_path, json=body, headers=headers, **kwargs)

    def put(self, url_path: str, body: Optional[dict] = None, headers: Optional[dict] = None, **kwargs) -> Response:
        return self._execute(method='put', endpoint=url_path, json=body, headers=headers, **kwargs)

    def get(self, url_path: str, headers: Optional[dict] = None, **kwargs) -> Response:
        return self._execute(method='get', endpoint=url_path, headers=headers, **kwargs)

    @retry(
        retry=retry_if_exception(_should_retry_exception),
        stop=_RETRY_STOP_STRATEGY,
        wait=_RETRY_WAIT_STRATEGY,
        reraise=True,
        before_sleep=_retry_before_sleep,
    )
    def _execute(
        self,
        method: str,
        endpoint: str,
        headers: Optional[dict] = None,
        without_auth: bool = False,
        hide_response_content_log: bool = False,
        **kwargs,
    ) -> Response:
        url = self.build_full_url(self.api_url, endpoint)
        logger.debug(
            'Executing request, %s',
            {'method': method.upper(), 'url': url},
        )

        timeout = self.timeout
        if 'timeout' in kwargs:
            timeout = kwargs['timeout']
            del kwargs['timeout']

        try:
            headers = self.get_request_headers(headers, without_auth=without_auth)
            request = _get_request_function()
            response = request(method=method, url=url, timeout=timeout, headers=headers, **kwargs)

            content = 'HIDDEN' if hide_response_content_log else response.text
            logger.debug(
                'Receiving response, %s',
                {'status_code': response.status_code, 'url': url, 'content': content},
            )

            response.raise_for_status()
            return response
        except Exception as e:
            self._handle_exception(e)

    def get_request_headers(self, additional_headers: Optional[dict] = None, **kwargs) -> dict[str, str]:
        if additional_headers is None:
            return self.MANDATORY_HEADERS.copy()
        return {**self.MANDATORY_HEADERS, **additional_headers}

    def build_full_url(self, url: str, endpoint: str) -> str:
        return f'{url}/{endpoint}'

    def _handle_exception(self, e: Exception) -> None:
        if isinstance(e, exceptions.Timeout):
            raise RequestTimeoutError from e
        if isinstance(e, exceptions.HTTPError):
            raise self._get_http_exception(e) from e
        if isinstance(e, exceptions.SSLError):
            raise RequestSslError from e
        if isinstance(e, exceptions.ConnectionError):
            raise RequestConnectionError from e

        raise e

    @staticmethod
    def _get_http_exception(e: exceptions.HTTPError) -> RequestError:
        if e.response.status_code == 401:
            return HttpUnauthorizedError(e.response.text, e.response)

        return RequestHttpError(e.response.status_code, e.response.text, e.response)
