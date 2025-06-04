import json
from copy import deepcopy
from typing import TYPE_CHECKING, Optional, Union
from uuid import UUID

from requests import Response

from cycode.cli import consts
from cycode.cli.config import configuration_manager
from cycode.cli.exceptions.custom_exceptions import CycodeError, RequestHttpError
from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
from cycode.cyclient import models
from cycode.cyclient.cycode_client_base import CycodeClientBase
from cycode.cyclient.logger import logger

if TYPE_CHECKING:
    from cycode.cyclient.scan_config_base import ScanConfigBase


class ScanClient:
    def __init__(
        self, scan_cycode_client: CycodeClientBase, scan_config: 'ScanConfigBase', hide_response_log: bool = True
    ) -> None:
        self.scan_cycode_client = scan_cycode_client
        self.scan_config = scan_config

        self._SCAN_SERVICE_CLI_CONTROLLER_PATH = 'api/v1/cli-scan'
        self._DETECTIONS_SERVICE_CLI_CONTROLLER_PATH = 'api/v1/detections/cli'
        self._POLICIES_SERVICE_CONTROLLER_PATH_V3 = 'api/v3/policies'

        self._hide_response_log = hide_response_log

    @staticmethod
    def get_scan_flow_type(should_use_sync_flow: bool = False) -> str:
        if should_use_sync_flow:
            return '/sync'

        return ''

    def get_scan_service_url_path(self, scan_type: str, should_use_sync_flow: bool = False) -> str:
        service_path = self.scan_config.get_service_name(scan_type)
        flow_type = self.get_scan_flow_type(should_use_sync_flow)
        return f'{service_path}/{self._SCAN_SERVICE_CLI_CONTROLLER_PATH}{flow_type}'

    def content_scan(self, scan_type: str, file_name: str, content: str, is_git_diff: bool = True) -> models.ScanResult:
        path = f'{self.get_scan_service_url_path(scan_type)}/content'
        body = {'name': file_name, 'content': content, 'is_git_diff': is_git_diff}
        response = self.scan_cycode_client.post(
            url_path=path, body=body, hide_response_content_log=self._hide_response_log
        )
        return self.parse_scan_response(response)

    def get_scan_aggregation_report_url(self, aggregation_id: str, scan_type: str) -> models.ScanReportUrlResponse:
        response = self.scan_cycode_client.get(
            url_path=self.get_scan_aggregation_report_url_path(aggregation_id, scan_type)
        )
        return models.ScanReportUrlResponseSchema().build_dto(response.json())

    def get_zipped_file_scan_async_url_path(self, scan_type: str, should_use_sync_flow: bool = False) -> str:
        async_scan_type = self.scan_config.get_async_scan_type(scan_type)
        async_entity_type = self.scan_config.get_async_entity_type(scan_type)
        scan_service_url_path = self.get_scan_service_url_path(scan_type, should_use_sync_flow=should_use_sync_flow)
        return f'{scan_service_url_path}/{async_scan_type}/{async_entity_type}'

    def get_zipped_file_scan_sync_url_path(self, scan_type: str) -> str:
        server_scan_type = self.scan_config.get_async_scan_type(scan_type)
        scan_service_url_path = self.get_scan_service_url_path(scan_type, should_use_sync_flow=True)
        return f'{scan_service_url_path}/{server_scan_type}/repository'

    def zipped_file_scan_sync(
        self,
        zip_file: InMemoryZip,
        scan_type: str,
        scan_parameters: dict,
        is_git_diff: bool = False,
    ) -> models.ScanResultsSyncFlow:
        files = {'file': ('multiple_files_scan.zip', zip_file.read())}

        scan_parameters = deepcopy(scan_parameters)  # avoid mutating the original dict
        if 'report' in scan_parameters:
            del scan_parameters['report']  # BE raises validation error instead of ignoring it

        response = self.scan_cycode_client.post(
            url_path=self.get_zipped_file_scan_sync_url_path(scan_type),
            data={
                'is_git_diff': is_git_diff,
                'scan_parameters': json.dumps(scan_parameters),
            },
            files=files,
            hide_response_content_log=self._hide_response_log,
            timeout=configuration_manager.get_sync_scan_timeout_in_seconds(),
        )
        return models.ScanResultsSyncFlowSchema().load(response.json())

    @staticmethod
    def _create_compression_manifest_string(zip_file: InMemoryZip) -> str:
        return json.dumps(
            {
                'file_count_by_extension': zip_file.extension_statistics,
                'file_count': zip_file.files_count,
            }
        )

    def zipped_file_scan_async(
        self,
        zip_file: InMemoryZip,
        scan_type: str,
        scan_parameters: dict,
        is_git_diff: bool = False,
        is_commit_range: bool = False,
    ) -> models.ScanInitializationResponse:
        files = {'file': ('multiple_files_scan.zip', zip_file.read())}

        response = self.scan_cycode_client.post(
            url_path=self.get_zipped_file_scan_async_url_path(scan_type),
            data={
                'is_git_diff': is_git_diff,
                'scan_parameters': json.dumps(scan_parameters),
                'is_commit_range': is_commit_range,
                'compression_manifest': self._create_compression_manifest_string(zip_file),
            },
            files=files,
        )
        return models.ScanInitializationResponseSchema().load(response.json())

    def commit_range_scan_async(
        self,
        from_commit_zip_file: InMemoryZip,
        to_commit_zip_file: InMemoryZip,
        scan_type: str,
        scan_parameters: dict,
        is_git_diff: bool = False,
    ) -> models.ScanInitializationResponse:
        """Commit range scan.
        Used by SCA and SAST scans.

        For SCA:
        - from_commit_zip_file is file content
        - to_commit_zip_file is file content

        For SAST:
        - from_commit_zip_file is file content
        - to_commit_zip_file is diff content

        Note:
            Compression manifest is supported only for SAST scans.
        """
        url_path = f'{self.get_scan_service_url_path(scan_type)}/{scan_type}/repository/commit-range'
        files = {
            'file_from_commit': ('multiple_files_scan.zip', from_commit_zip_file.read()),
            'file_to_commit': ('multiple_files_scan.zip', to_commit_zip_file.read()),
        }
        response = self.scan_cycode_client.post(
            url_path=url_path,
            data={
                'is_git_diff': is_git_diff,
                'scan_parameters': json.dumps(scan_parameters),
                'compression_manifest': self._create_compression_manifest_string(from_commit_zip_file),
            },
            files=files,
        )
        return models.ScanInitializationResponseSchema().load(response.json())

    def get_scan_details_path(self, scan_type: str, scan_id: str) -> str:
        return f'{self.get_scan_service_url_path(scan_type)}/{scan_id}'

    def get_scan_aggregation_report_url_path(self, aggregation_id: str, scan_type: str) -> str:
        return f'{self.get_scan_service_url_path(scan_type)}/reportUrlByAggregationId/{aggregation_id}'

    def get_scan_details(self, scan_type: str, scan_id: str) -> models.ScanDetailsResponse:
        path = self.get_scan_details_path(scan_type, scan_id)
        response = self.scan_cycode_client.get(url_path=path)
        return models.ScanDetailsResponseSchema().load(response.json())

    def get_detection_rules_path(self) -> str:
        return (
            f'{self.scan_config.get_detections_prefix()}/'
            f'{self._POLICIES_SERVICE_CONTROLLER_PATH_V3}/'
            f'detection_rules/byIds'
        )

    def get_supported_modules_preferences(self) -> models.SupportedModulesPreferences:
        response = self.scan_cycode_client.get(url_path='preferences/api/v1/supportedmodules')
        return models.SupportedModulesPreferencesSchema().load(response.json())

    @staticmethod
    def get_ai_remediation_path(detection_id: str) -> str:
        return f'scm-remediator/api/v1/ContentRemediation/preview/{detection_id}'

    def get_ai_remediation(self, detection_id: UUID, *, fix: bool = False) -> str:
        path = self.get_ai_remediation_path(detection_id.hex)

        data = {
            'resolving_parameters': {
                'get_diff': True,
                'use_code_snippet': True,
                'add_diff_header': True,
            }
        }
        if not fix:
            data['resolving_parameters']['remediation_action'] = 'ReplyWithRemediationDetails'

        response = self.scan_cycode_client.get(
            url_path=path, json=data, timeout=configuration_manager.get_ai_remediation_timeout_in_seconds()
        )
        return response.text.strip()

    @staticmethod
    def _get_policy_type_by_scan_type(scan_type: str) -> str:
        scan_type_to_policy_type = {
            consts.IAC_SCAN_TYPE: 'IaC',
            consts.SCA_SCAN_TYPE: 'SCA',
            consts.SECRET_SCAN_TYPE: 'SecretDetection',
            consts.SAST_SCAN_TYPE: 'SAST',
        }

        if scan_type not in scan_type_to_policy_type:
            raise CycodeError('Invalid scan type')

        return scan_type_to_policy_type[scan_type]

    @staticmethod
    def parse_detection_rules_response(response: Response) -> list[models.DetectionRule]:
        return models.DetectionRuleSchema().load(response.json(), many=True)

    def get_detection_rules(self, detection_rules_ids: Union[set[str], list[str]]) -> list[models.DetectionRule]:
        response = self.scan_cycode_client.get(
            url_path=self.get_detection_rules_path(),
            params={'ids': detection_rules_ids},
            hide_response_content_log=self._hide_response_log,
        )

        return self.parse_detection_rules_response(response)

    def get_scan_detections_path(self) -> str:
        return f'{self.scan_config.get_detections_prefix()}/{self._DETECTIONS_SERVICE_CLI_CONTROLLER_PATH}'

    def get_scan_detections_list_path(self) -> str:
        return f'{self.get_scan_detections_path()}/detections'

    def get_scan_raw_detections(self, scan_id: str) -> list[dict]:
        params = {'scan_id': scan_id}

        page_size = 200

        raw_detections = []

        page_number = 0
        last_response_size = 0
        while page_number == 0 or last_response_size == page_size:
            params['page_size'] = page_size
            params['page_number'] = page_number

            response = self.scan_cycode_client.get(
                url_path=self.get_scan_detections_list_path(),
                params=params,
                hide_response_content_log=self._hide_response_log,
            ).json()
            raw_detections.extend(response)

            page_number += 1
            last_response_size = len(response)

        return raw_detections

    def get_report_scan_status_path(self, scan_type: str, scan_id: str) -> str:
        return f'{self.get_scan_service_url_path(scan_type)}/{scan_id}/status'

    def report_scan_status(self, scan_type: str, scan_id: str, scan_status: dict) -> None:
        self.scan_cycode_client.post(
            url_path=self.get_report_scan_status_path(scan_type, scan_id),
            body=scan_status,
        )

    @staticmethod
    def parse_scan_response(response: Response) -> models.ScanResult:
        return models.ScanResultSchema().load(response.json())

    def get_scan_configuration_path(self, scan_type: str) -> str:
        correct_scan_type = self.scan_config.get_async_scan_type(scan_type)
        return f'{self.get_scan_service_url_path(scan_type)}/{correct_scan_type}/configuration'

    def get_scan_configuration(self, scan_type: str) -> models.ScanConfiguration:
        response = self.scan_cycode_client.get(
            url_path=self.get_scan_configuration_path(scan_type),
            hide_response_content_log=self._hide_response_log,
        )
        return models.ScanConfigurationSchema().load(response.json())

    def get_scan_configuration_safe(self, scan_type: str) -> Optional['models.ScanConfiguration']:
        try:
            return self.get_scan_configuration(scan_type)
        except RequestHttpError as e:
            if e.status_code == 404:
                logger.debug(
                    'Remote scan configuration is not supported for this scan type: %s', {'scan_type': scan_type}
                )
            else:
                logger.debug('Failed to get remote scan configuration: %s', {'scan_type': scan_type}, exc_info=e)
