from . import models
from .client import CycodeClient
from requests import Response
from cli.zip_file import InMemoryZip


class ScanClient:

    def __init__(self, client_id: str = None,
                 client_secret: str = None):
        self.cycode_client = CycodeClient(client_secret=client_secret, client_id=client_id)

    def content_scan(self, scan_type: str, file_name: str, content: str, is_git_diff: bool = True):
        path = f"{self.get_service_name(scan_type)}/api/v1/scan/content"
        body = {'name': file_name, 'content': content, 'is_git_diff': is_git_diff}
        response = self.cycode_client.post(url_path=path, body=body)
        return self.parse_scan_response(response)

    def file_scan(self, scan_type: str, path: str) -> models.ScanResult:
        url_path = f"{self.get_service_name(scan_type)}/api/v1/scan"
        files = {'file': open(path, 'rb')}
        response = self.cycode_client.post(url_path=url_path, files=files)
        return self.parse_scan_response(response)

    def zipped_file_scan(self, scan_type: str, zip_file: InMemoryZip, scan_id: str,
                         is_git_diff: bool = False) -> models.ZippedFileScanResult:
        url_path = f"{self.get_service_name(scan_type)}/api/v1/scan/zipped-file"
        files = {'file': ('multiple_files_scan.zip', zip_file.read())}
        response = self.cycode_client.post(url_path=url_path, data={'scan_id': scan_id, 'is_git_diff': is_git_diff},
                                           files=files)
        return self.parse_zipped_file_scan_response(response)

    def commit_range_zipped_file_scan(self, scan_type: str, zip_file: InMemoryZip,
                                      scan_id: str) -> models.ZippedFileScanResult:
        url_path = f"{self.get_service_name(scan_type)}/api/v1/scan/commit-range-zipped-file"
        files = {'file': ('multiple_files_scan.zip', zip_file.read())}
        response = self.cycode_client.post(url_path=url_path, data={'scan_id': scan_id}, files=files)
        return self.parse_zipped_file_scan_response(response)

    def report_scan_status(self, scan_type: str, scan_id: str, scan_status: dict):
        url_path = f"{self.get_service_name(scan_type)}/api/v1/scan/{scan_id}/status"
        self.cycode_client.post(url_path=url_path, body=scan_status)

    @staticmethod
    def parse_scan_response(response: Response) -> models.ScanResult:
        return models.ScanResultSchema().load(response.json())

    @staticmethod
    def parse_zipped_file_scan_response(response: Response):
        return models.ZippedFileScanResultSchema().load(response.json())

    @staticmethod
    def get_service_name(scan_type):
        return 'secret' if scan_type == 'secret' else 'iac'
