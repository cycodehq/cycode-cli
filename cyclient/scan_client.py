import requests.exceptions
from requests import Response
from . import models
from .cycode_token_based_client import CycodeTokenBasedClient
from cli.zip_file import InMemoryZip
from cli.exceptions.custom_exceptions import CycodeError, HttpUnauthorizedError


class ScanClient:

    SCAN_CONTROLLER_PATH = 'api/v1/scan'

    def __init__(self, client_id: str = None, client_secret: str = None):
        self.cycode_client = CycodeTokenBasedClient(client_id, client_secret)

    def content_scan(self, scan_type: str, file_name: str, content: str, is_git_diff: bool = True):
        path = f"{self.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/content"
        body = {'name': file_name, 'content': content, 'is_git_diff': is_git_diff}
        try:
            response = self.cycode_client.post(url_path=path, body=body)
            return self.parse_scan_response(response)
        except Exception as e:
            self._handle_exception(e)

    def file_scan(self, scan_type: str, path: str) -> models.ScanResult:
        url_path = f"{self.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}"
        files = {'file': open(path, 'rb')}
        try:
            response = self.cycode_client.post(url_path=url_path, files=files)
            return self.parse_scan_response(response)
        except Exception as e:
            self._handle_exception(e)

    def zipped_file_scan(self, scan_type: str, zip_file: InMemoryZip, scan_id: str,
                         is_git_diff: bool = False) -> models.ZippedFileScanResult:
        url_path = f"{self.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/zipped-file"
        files = {'file': ('multiple_files_scan.zip', zip_file.read())}
        try:
            response = self.cycode_client.post(url_path=url_path, data={'scan_id': scan_id, 'is_git_diff': is_git_diff},
                                 files=files)
            return self.parse_zipped_file_scan_response(response)
        except Exception as e:
            self._handle_exception(e)

    def commit_range_zipped_file_scan(self, scan_type: str, zip_file: InMemoryZip,
                                      scan_id: str) -> models.ZippedFileScanResult:
        url_path = f"{self.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/commit-range-zipped-file"
        files = {'file': ('multiple_files_scan.zip', zip_file.read())}
        try:
            response = self.cycode_client.post(url_path=url_path, data={'scan_id': scan_id}, files=files)
            return self.parse_zipped_file_scan_response(response)
        except Exception as e:
            self._handle_exception(e)

    def report_scan_status(self, scan_type: str, scan_id: str, scan_status: dict):
        url_path = f"{self.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/{scan_id}/status"
        try:
            self.cycode_client.post(url_path=url_path, body=scan_status)
        except Exception as e:
            self._handle_exception(e)

    @staticmethod
    def parse_scan_response(response: Response) -> models.ScanResult:
        return models.ScanResultSchema().load(response.json())

    @staticmethod
    def parse_zipped_file_scan_response(response: Response) -> models.ZippedFileScanResult:
        return models.ZippedFileScanResultSchema().load(response.json())

    @staticmethod
    def get_service_name(scan_type):
        return 'secret' if scan_type == 'secret' else 'iac'

    def _handle_exception(self, e: Exception):
        if isinstance(e, requests.exceptions.Timeout):
            raise CycodeError(504, "Timeout Error")
        elif isinstance(e, requests.exceptions.HTTPError):
            self._handle_http_exception(e)

    @staticmethod
    def _handle_http_exception(e: requests.exceptions.HTTPError):
        if e.response.status_code == 401:
            raise HttpUnauthorizedError(e.response.text)
        else:
            raise CycodeError(e.response.status_code, e.response.text)