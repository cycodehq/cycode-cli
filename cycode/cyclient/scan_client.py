import json
from typing import TYPE_CHECKING, List, Optional

from requests import Response

from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
from cycode.cyclient import models
from cycode.cyclient.cycode_client_base import CycodeClientBase

if TYPE_CHECKING:
    from .scan_config_base import ScanConfigBase


class ScanClient:
    def __init__(
        self, scan_cycode_client: CycodeClientBase, scan_config: 'ScanConfigBase', hide_response_log: bool = True
    ) -> None:
        self.scan_cycode_client = scan_cycode_client
        self.scan_config = scan_config

        self.SCAN_CONTROLLER_PATH = 'api/v1/scan'
        self.DETECTIONS_SERVICE_CONTROLLER_PATH = 'api/v1/detections'

        self._hide_response_log = hide_response_log

    def content_scan(self, scan_type: str, file_name: str, content: str, is_git_diff: bool = True) -> models.ScanResult:
        path = f'{self.scan_config.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/content'
        body = {'name': file_name, 'content': content, 'is_git_diff': is_git_diff}
        response = self.scan_cycode_client.post(
            url_path=path, body=body, hide_response_content_log=self._hide_response_log
        )
        return self.parse_scan_response(response)

    def get_zipped_file_scan_url_path(self, scan_type: str) -> str:
        return f'{self.scan_config.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/zipped-file'

    def zipped_file_scan(
        self, scan_type: str, zip_file: InMemoryZip, scan_id: str, scan_parameters: dict, is_git_diff: bool = False
    ) -> models.ZippedFileScanResult:
        files = {'file': ('multiple_files_scan.zip', zip_file.read())}

        response = self.scan_cycode_client.post(
            url_path=self.get_zipped_file_scan_url_path(scan_type),
            data={'scan_id': scan_id, 'is_git_diff': is_git_diff, 'scan_parameters': json.dumps(scan_parameters)},
            files=files,
            hide_response_content_log=self._hide_response_log,
        )

        return self.parse_zipped_file_scan_response(response)

    def get_zipped_file_scan_async_url_path(self, scan_type: str) -> str:
        async_scan_type = self.scan_config.get_async_scan_type(scan_type)
        async_entity_type = self.scan_config.get_async_entity_type(scan_type)

        url_prefix = self.scan_config.get_scans_prefix()
        return f'{url_prefix}/{self.SCAN_CONTROLLER_PATH}/{async_scan_type}/{async_entity_type}'

    def zipped_file_scan_async(
        self, zip_file: InMemoryZip, scan_type: str, scan_parameters: dict, is_git_diff: bool = False
    ) -> models.ScanInitializationResponse:
        files = {'file': ('multiple_files_scan.zip', zip_file.read())}
        response = self.scan_cycode_client.post(
            url_path=self.get_zipped_file_scan_async_url_path(scan_type),
            data={'is_git_diff': is_git_diff, 'scan_parameters': json.dumps(scan_parameters)},
            files=files,
        )
        return models.ScanInitializationResponseSchema().load(response.json())

    def multiple_zipped_file_scan_async(
        self,
        from_commit_zip_file: InMemoryZip,
        to_commit_zip_file: InMemoryZip,
        scan_type: str,
        scan_parameters: dict,
        is_git_diff: bool = False,
    ) -> models.ScanInitializationResponse:
        url_path = (
            f'{self.scan_config.get_scans_prefix()}/{self.SCAN_CONTROLLER_PATH}/{scan_type}/repository/commit-range'
        )
        files = {
            'file_from_commit': ('multiple_files_scan.zip', from_commit_zip_file.read()),
            'file_to_commit': ('multiple_files_scan.zip', to_commit_zip_file.read()),
        }
        response = self.scan_cycode_client.post(
            url_path=url_path,
            data={'is_git_diff': is_git_diff, 'scan_parameters': json.dumps(scan_parameters)},
            files=files,
        )
        return models.ScanInitializationResponseSchema().load(response.json())

    def get_scan_details_path(self, scan_id: str) -> str:
        return f'{self.scan_config.get_scans_prefix()}/{self.SCAN_CONTROLLER_PATH}/{scan_id}'

    def get_scan_details(self, scan_id: str) -> models.ScanDetailsResponse:
        response = self.scan_cycode_client.get(url_path=self.get_scan_details_path(scan_id))
        return models.ScanDetailsResponseSchema().load(response.json())

    def get_scan_detections_path(self) -> str:
        return f'{self.scan_config.get_detections_prefix()}/{self.DETECTIONS_SERVICE_CONTROLLER_PATH}'

    def get_scan_detections(self, scan_id: str) -> List[dict]:
        params = {'scan_id': scan_id}

        page_size = 200

        detections = []

        page_number = 0
        last_response_size = 0
        while page_number == 0 or last_response_size == page_size:
            params['page_size'] = page_size
            params['page_number'] = page_number

            response = self.scan_cycode_client.get(
                url_path=self.get_scan_detections_path(),
                params=params,
                hide_response_content_log=self._hide_response_log,
            ).json()
            detections.extend(response)

            page_number += 1
            last_response_size = len(response)

        return detections

    def get_get_scan_detections_count_path(self) -> str:
        return f'{self.scan_config.get_detections_prefix()}/{self.DETECTIONS_SERVICE_CONTROLLER_PATH}/count'

    def get_scan_detections_count(self, scan_id: str) -> int:
        response = self.scan_cycode_client.get(
            url_path=self.get_get_scan_detections_count_path(), params={'scan_id': scan_id}
        )
        return response.json().get('count', 0)

    def commit_range_zipped_file_scan(
        self, scan_type: str, zip_file: InMemoryZip, scan_id: str
    ) -> models.ZippedFileScanResult:
        url_path = (
            f'{self.scan_config.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/commit-range-zipped-file'
        )
        files = {'file': ('multiple_files_scan.zip', zip_file.read())}
        response = self.scan_cycode_client.post(
            url_path=url_path, data={'scan_id': scan_id}, files=files, hide_response_content_log=self._hide_response_log
        )
        return self.parse_zipped_file_scan_response(response)

    def get_report_scan_status_path(self, scan_type: str, scan_id: str) -> str:
        return f'{self.scan_config.get_service_name(scan_type)}/{self.SCAN_CONTROLLER_PATH}/{scan_id}/status'

    def report_scan_status(self, scan_type: str, scan_id: str, scan_status: dict) -> None:
        self.scan_cycode_client.post(url_path=self.get_report_scan_status_path(scan_type, scan_id), body=scan_status)

    @staticmethod
    def parse_scan_response(response: Response) -> models.ScanResult:
        return models.ScanResultSchema().load(response.json())

    @staticmethod
    def parse_zipped_file_scan_response(response: Response) -> models.ZippedFileScanResult:
        return models.ZippedFileScanResultSchema().load(response.json())

    @staticmethod
    def get_service_name(scan_type: str) -> Optional[str]:
        # TODO(MarshalX): get_service_name should be removed from ScanClient? Because it exists in ScanConfig
        if scan_type == 'secret':
            return 'secret'
        if scan_type == 'iac':
            return 'iac'
        if scan_type == 'sca' or scan_type == 'sast':
            return 'scans'

        return None
