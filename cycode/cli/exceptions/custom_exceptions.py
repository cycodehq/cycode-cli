from requests import Response

from cycode.cli.models import CliError, CliErrors


class CycodeError(Exception):
    """Base class for all custom exceptions"""


class RequestError(CycodeError): ...


class RequestTimeout(RequestError): ...


class RequestConnectionError(RequestError): ...


class RequestSslError(RequestConnectionError): ...


class RequestHttpError(RequestError):
    def __init__(self, status_code: int, error_message: str, response: Response) -> None:
        self.status_code = status_code
        self.error_message = error_message
        self.response = response
        super().__init__(self.error_message)

    def __str__(self) -> str:
        return (
            f'error occurred during the request. status code: {self.status_code}, error message: '
            f'{self.error_message}'
        )


class ScanAsyncError(CycodeError):
    def __init__(self, error_message: str) -> None:
        self.error_message = error_message
        super().__init__(self.error_message)

    def __str__(self) -> str:
        return f'error occurred during the scan. error message: {self.error_message}'


class ReportAsyncError(CycodeError):
    pass


class HttpUnauthorizedError(RequestError):
    def __init__(self, error_message: str, response: Response) -> None:
        self.status_code = 401
        self.error_message = error_message
        self.response = response
        super().__init__(self.error_message)

    def __str__(self) -> str:
        return 'Http Unauthorized Error'


class ZipTooLargeError(CycodeError):
    def __init__(self, size_limit: int) -> None:
        self.size_limit = size_limit
        super().__init__()

    def __str__(self) -> str:
        return f'The size of zip to scan is too large, size limit: {self.size_limit}'


class AuthProcessError(CycodeError):
    def __init__(self, error_message: str) -> None:
        self.error_message = error_message
        super().__init__()

    def __str__(self) -> str:
        return f'Something went wrong during the authentication process, error message: {self.error_message}'


class TfplanKeyError(CycodeError):
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        super().__init__()

    def __str__(self) -> str:
        return f'Error occurred while parsing terraform plan file. Path: {self.file_path}'


KNOWN_USER_FRIENDLY_REQUEST_ERRORS: CliErrors = {
    RequestHttpError: CliError(
        soft_fail=True,
        code='cycode_error',
        message='Cycode was unable to complete this scan. Please try again by executing the `cycode scan` command',
    ),
    RequestTimeout: CliError(
        soft_fail=True,
        code='timeout_error',
        message='The request timed out. Please try again by executing the `cycode scan` command',
    ),
    HttpUnauthorizedError: CliError(
        soft_fail=True,
        code='auth_error',
        message='Unable to authenticate to Cycode, your token is either invalid or has expired. '
        'Please re-generate your token and reconfigure it by running the `cycode configure` command',
    ),
    RequestSslError: CliError(
        soft_fail=True,
        code='ssl_error',
        message='An SSL error occurred when trying to connect to the Cycode API. '
        'If you use an on-premises installation or a proxy that intercepts SSL traffic '
        'you should use the CURL_CA_BUNDLE environment variable to specify path to a valid .pem or similar.',
    ),
}
