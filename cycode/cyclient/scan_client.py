import json
from typing import TYPE_CHECKING, List, Optional, Set, Union

from requests import Response

from cycode.cli import consts
from cycode.cli.exceptions.custom_exceptions import CycodeError
from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
from cycode.cyclient import models
from cycode.cyclient.cycode_client_base import CycodeClientBase

if TYPE_CHECKING:
    from cycode.cyclient.scan_config_base import ScanConfigBase


class ScanClient:
    def __init__(
        self, scan_cycode_client: CycodeClientBase, scan_config: 'ScanConfigBase', hide_response_log: bool = True
    ) -> None:
        self.scan_cycode_client = scan_cycode_client
        self.scan_config = scan_config

        self._SCAN_SERVICE_CONTROLLER_PATH = 'api/v1/scan'
        self._SCAN_SERVICE_CLI_CONTROLLER_PATH = 'api/v1/cli-scan'

        self._DETECTIONS_SERVICE_CONTROLLER_PATH = 'api/v1/detections'
        self._DETECTIONS_SERVICE_CLI_CONTROLLER_PATH = 'api/v1/detections/cli'

        self.POLICIES_SERVICE_CONTROLLER_PATH_V3 = 'api/v3/policies'

        self._hide_response_log = hide_response_log

    def get_scan_controller_path(self, scan_type: str) -> str:
        if scan_type == consts.INFRA_CONFIGURATION_SCAN_TYPE:
            # we don't use async flow for IaC scan yet
            return self._SCAN_SERVICE_CONTROLLER_PATH

        return self._SCAN_SERVICE_CLI_CONTROLLER_PATH

    def get_detections_service_controller_path(self, scan_type: str) -> str:
        if scan_type == consts.INFRA_CONFIGURATION_SCAN_TYPE:
            # we don't use async flow for IaC scan yet
            return self._DETECTIONS_SERVICE_CONTROLLER_PATH

        return self._DETECTIONS_SERVICE_CLI_CONTROLLER_PATH

    def get_scan_service_url_path(self, scan_type: str, should_use_scan_service: bool = False) -> str:
        service_path = self.scan_config.get_service_name(scan_type, should_use_scan_service)
        controller_path = self.get_scan_controller_path(scan_type)
        return f'{service_path}/{controller_path}'

    def content_scan(self, scan_type: str, file_name: str, content: str, is_git_diff: bool = True) -> models.ScanResult:
        path = f'{self.get_scan_service_url_path(scan_type)}/content'
        body = {'name': file_name, 'content': content, 'is_git_diff': is_git_diff}
        response = self.scan_cycode_client.post(
            url_path=path, body=body, hide_response_content_log=self._hide_response_log
        )
        return self.parse_scan_response(response)

    def get_zipped_file_scan_url_path(self, scan_type: str) -> str:
        return f'{self.get_scan_service_url_path(scan_type)}/zipped-file'

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

    def get_scan_report_url(self, scan_id: str, scan_type: str) -> models.ScanReportUrlResponse:
        response = self.scan_cycode_client.get(url_path=self.get_scan_report_url_path(scan_id, scan_type))
        return models.ScanReportUrlResponseSchema().build_dto(response.json())

    def get_zipped_file_scan_async_url_path(self, scan_type: str) -> str:
        async_scan_type = self.scan_config.get_async_scan_type(scan_type)
        async_entity_type = self.scan_config.get_async_entity_type(scan_type)
        scan_service_url_path = self.get_scan_service_url_path(scan_type, True)
        return f'{scan_service_url_path}/{async_scan_type}/{async_entity_type}'

    def zipped_file_scan_async(
        self,
        zip_file: InMemoryZip,
        scan_type: str,
        scan_parameters: dict,
        is_git_diff: bool = False,
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
        url_path = f'{self.get_scan_service_url_path(scan_type)}/{scan_type}/repository/commit-range'
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

    def get_scan_details_path(self, scan_type: str, scan_id: str) -> str:
        return f'{self.get_scan_service_url_path(scan_type, should_use_scan_service=True)}/{scan_id}'

    def get_scan_report_url_path(self, scan_id: str, scan_type: str) -> str:
        return f'{self.get_scan_service_url_path(scan_type, should_use_scan_service=True)}/reportUrl/{scan_id}'

    def get_scan_details(self, scan_type: str, scan_id: str) -> models.ScanDetailsResponse:
        path = self.get_scan_details_path(scan_type, scan_id)
        response = self.scan_cycode_client.get(url_path=path)
        return models.ScanDetailsResponseSchema().load(response.json())

    def get_detection_rules_path(self) -> str:
        return (
            f'{self.scan_config.get_detections_prefix()}/'
            f'{self.POLICIES_SERVICE_CONTROLLER_PATH_V3}/'
            f'detection_rules'
        )

    @staticmethod
    def _get_policy_type_by_scan_type(scan_type: str) -> str:
        scan_type_to_policy_type = {
            consts.INFRA_CONFIGURATION_SCAN_TYPE: 'IaC',
            consts.SCA_SCAN_TYPE: 'SCA',
            consts.SECRET_SCAN_TYPE: 'SecretDetection',
            consts.SAST_SCAN_TYPE: 'SAST',
        }

        if scan_type not in scan_type_to_policy_type:
            raise CycodeError('Invalid scan type')

        return scan_type_to_policy_type[scan_type]

    @staticmethod
    def _filter_detection_rules_by_ids(
        detection_rules: List[models.DetectionRule], detection_rules_ids: Union[Set[str], List[str]]
    ) -> List[models.DetectionRule]:
        ids = set(detection_rules_ids)  # cast to set to perform faster search
        return [rule for rule in detection_rules if rule.detection_rule_id in ids]

    @staticmethod
    def parse_detection_rules_response(response: Response) -> List[models.DetectionRule]:
        return models.DetectionRuleSchema().load(response.json(), many=True)

    def get_detection_rules(
        self, scan_type: str, detection_rules_ids: Union[Set[str], List[str]]
    ) -> List[models.DetectionRule]:
        # TODO(MarshalX): use filter by list of IDs instead of policy_type when BE will be ready
        params = {
            'include_hidden': False,
            'include_only_enabled_detection_rules': True,
            'page_number': 0,
            'page_size': 5000,
            'policy_types_v2': self._get_policy_type_by_scan_type(scan_type),
        }
        response = self.scan_cycode_client.get(
            url_path=self.get_detection_rules_path(),
            params=params,
            hide_response_content_log=self._hide_response_log,
        )

        # we are filtering rules by ids in-place for smooth migration when backend will be ready
        return self._filter_detection_rules_by_ids(self.parse_detection_rules_response(response), detection_rules_ids)

    def get_scan_detections_path(self, scan_type: str) -> str:
        return f'{self.scan_config.get_detections_prefix()}/{self.get_detections_service_controller_path(scan_type)}'

    @staticmethod
    def get_scan_detections_list_path_suffix(scan_type: str) -> str:
        # we don't use async flow for IaC scan yet
        if scan_type == consts.INFRA_CONFIGURATION_SCAN_TYPE:
            return ''

        return '/detections'

    def get_scan_detections_list_path(self, scan_type: str) -> str:
        return f'{self.get_scan_detections_path(scan_type)}{self.get_scan_detections_list_path_suffix(scan_type)}'

    def get_scan_detections(self, scan_type: str, scan_id: str) -> List[dict]:
        params = {'scan_id': scan_id}

        page_size = 200

        detections = []

        page_number = 0
        last_response_size = 0
        while page_number == 0 or last_response_size == page_size:
            params['page_size'] = page_size
            params['page_number'] = page_number

            response = self.scan_cycode_client.get(
                url_path=self.get_scan_detections_list_path(scan_type),
                params=params,
                hide_response_content_log=self._hide_response_log,
            ).json()
            detections.extend(response)

            page_number += 1
            last_response_size = len(response)

        return detections

    def get_scan_detections_count_path(self, scan_type: str) -> str:
        return f'{self.get_scan_detections_path(scan_type)}/count'

    def get_scan_detections_count(self, scan_type: str, scan_id: str) -> int:
        response = self.scan_cycode_client.get(
            url_path=self.get_scan_detections_count_path(scan_type), params={'scan_id': scan_id}
        )
        return response.json().get('count', 0)

    def commit_range_zipped_file_scan(
        self, scan_type: str, zip_file: InMemoryZip, scan_id: str
    ) -> models.ZippedFileScanResult:
        url_path = f'{self.get_scan_service_url_path(scan_type)}/commit-range-zipped-file'
        files = {'file': ('multiple_files_scan.zip', zip_file.read())}
        response = self.scan_cycode_client.post(
            url_path=url_path, data={'scan_id': scan_id}, files=files, hide_response_content_log=self._hide_response_log
        )
        return self.parse_zipped_file_scan_response(response)

    def get_report_scan_status_path(self, scan_type: str, scan_id: str, should_use_scan_service: bool = False) -> str:
        return f'{self.get_scan_service_url_path(scan_type, should_use_scan_service)}/{scan_id}/status'

    def report_scan_status(
        self, scan_type: str, scan_id: str, scan_status: dict, should_use_scan_service: bool = False
    ) -> None:
        self.scan_cycode_client.post(
            url_path=self.get_report_scan_status_path(
                scan_type, scan_id, should_use_scan_service=should_use_scan_service
            ),
            body=scan_status,
        )

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
