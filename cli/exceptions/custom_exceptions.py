
class CycodeError(Exception):
    def __init__(self, status_code: int, error_message: str):
        self.status_code = status_code
        self.error_message = error_message
        super().__init__(self.error_message)

    def __str__(self):
        return f'error occurred during scan request. status code: {self.status_code}, error message: ' \
               f'{self.error_message}'


class HttpUnauthorizedError(Exception):
    def __init__(self, error_message: str):
        self.status_code = 401
        self.error_message = error_message
        super().__init__(self.error_message)

    def __str__(self):
        return 'Http Unauthorized Error'


class ZipTooLargeError(Exception):
    def __init__(self, size_limit: int):
        self.size_limit = size_limit
        super().__init__()

    def __str__(self):
        return f'The size of zip to scan is too large, size limit: {self.size_limit}'
