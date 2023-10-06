from requests import Response


class CycodeError(Exception):
    """Base class for all custom exceptions"""


class NetworkError(CycodeError):
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


class HttpUnauthorizedError(CycodeError):
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
