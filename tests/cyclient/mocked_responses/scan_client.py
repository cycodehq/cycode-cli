import json
from pathlib import Path
from typing import Optional
from uuid import UUID, uuid4

import responses

from cycode.cyclient.scan_client import ScanClient
from tests.conftest import MOCKED_RESPONSES_PATH


def get_zipped_file_scan_async_url(scan_type: str, scan_client: ScanClient) -> str:
    api_url = scan_client.scan_cycode_client.api_url
    service_url = scan_client.get_zipped_file_scan_async_url_path(scan_type)
    return f'{api_url}/{service_url}'


def get_zipped_file_scan_async_response(url: str, scan_id: Optional[UUID] = None) -> responses.Response:
    if not scan_id:
        scan_id = uuid4()

    json_response = {
        'scan_id': str(scan_id),  # not always as expected due to _get_scan_id and passing scan_id to cxt of CLI
    }

    return responses.Response(method=responses.POST, url=url, json=json_response, status=200)


def get_scan_details_url(scan_type: str, scan_id: Optional[UUID], scan_client: ScanClient) -> str:
    api_url = scan_client.scan_cycode_client.api_url
    service_url = scan_client.get_scan_details_path(scan_type, str(scan_id))
    return f'{api_url}/{service_url}'


def get_scan_aggregation_report_url(aggregation_id: Optional[UUID], scan_client: ScanClient, scan_type: str) -> str:
    api_url = scan_client.scan_cycode_client.api_url
    service_url = scan_client.get_scan_aggregation_report_url_path(str(aggregation_id), scan_type)
    return f'{api_url}/{service_url}'


def get_scan_aggregation_report_url_response(url: str, aggregation_id: Optional[UUID] = None) -> responses.Response:
    if not aggregation_id:
        aggregation_id = uuid4()
    json_response = {'report_url': f'https://app.domain/cli-logs-aggregation/{aggregation_id}'}

    return responses.Response(method=responses.GET, url=url, json=json_response, status=200)


def get_scan_details_response(url: str, scan_id: Optional[UUID] = None) -> responses.Response:
    if not scan_id:
        scan_id = uuid4()

    json_response = {
        'id': str(scan_id),
        'scan_type': 'Secrets',
        'metadata': f'Path: {scan_id}, Folder: scans, Size: 465',
        'entity_type': 'ZippedFile',
        'entity_id': 'Repository',
        'parent_entity_id': 'Organization',
        'organization_id': 'Organization',
        'scm_provider': 'CycodeCli',
        'started_at': '2023-10-25T10:02:23.048282+00:00',
        'finished_at': '2023-10-25T10:02:26.867082+00:00',
        'scan_status': 'Completed',  # mark as completed to avoid mocking repeated requests
        'message': None,
        'results_count': 1,
        'scan_update_at': '2023-10-25T10:02:26.867216+00:00',
        'duration': {'days': 0, 'hours': 0, 'minutes': 0, 'seconds': 3, 'milliseconds': 818},
        'is_hidden': False,
        'is_initial_scan': False,
        'detection_messages': [],
    }

    return responses.Response(method=responses.GET, url=url, json=json_response, status=200)


def get_scan_detections_url(scan_client: ScanClient) -> str:
    api_url = scan_client.scan_cycode_client.api_url
    path = scan_client.get_scan_detections_list_path()
    return f'{api_url}/{path}'


def get_scan_detections_response(url: str, scan_id: UUID, zip_content_path: Path) -> responses.Response:
    with open(MOCKED_RESPONSES_PATH.joinpath('detections.json'), encoding='UTF-8') as f:
        content = f.read()
        content = content.replace('%FILEPATH%', str(zip_content_path.absolute().as_posix()))
        content = content.replace('%SCAN_ID%', str(scan_id))

        json_response = json.loads(content)

    return responses.Response(method=responses.GET, url=url, json=json_response, status=200)


def get_report_scan_status_url(scan_type: str, scan_id: UUID, scan_client: ScanClient) -> str:
    api_url = scan_client.scan_cycode_client.api_url
    service_url = scan_client.get_report_scan_status_path(scan_type, str(scan_id))
    return f'{api_url}/{service_url}'


def get_report_scan_status_response(url: str) -> responses.Response:
    return responses.Response(method=responses.POST, url=url, status=200)


def get_detection_rules_url(scan_client: ScanClient) -> str:
    api_url = scan_client.scan_cycode_client.api_url
    service_url = scan_client.get_detection_rules_path()
    return f'{api_url}/{service_url}'


def get_detection_rules_response(url: str) -> responses.Response:
    with open(MOCKED_RESPONSES_PATH.joinpath('detection_rules.json'), encoding='UTF-8') as f:
        json_response = json.load(f)

    return responses.Response(method=responses.GET, url=url, json=json_response, status=200)


def get_scan_configuration_url(scan_type: str, scan_client: ScanClient) -> str:
    api_url = scan_client.scan_cycode_client.api_url
    service_url = scan_client.get_scan_configuration_path(scan_type)
    return f'{api_url}/{service_url}'


def get_scan_configuration_response(url: str) -> responses.Response:
    json_response = {
        'scannable_extensions': None,
    }

    return responses.Response(method=responses.GET, url=url, json=json_response, status=200)


def mock_remote_config_responses(responses_module: responses, scan_type: str, scan_client: ScanClient) -> None:
    responses_module.add(get_scan_configuration_response(get_scan_configuration_url(scan_type, scan_client)))


def mock_scan_async_responses(
    responses_module: responses, scan_type: str, scan_client: ScanClient, scan_id: UUID, zip_content_path: Path
) -> None:
    mock_remote_config_responses(responses_module, scan_type, scan_client)
    responses_module.add(
        get_zipped_file_scan_async_response(get_zipped_file_scan_async_url(scan_type, scan_client), scan_id)
    )
    responses_module.add(get_scan_details_response(get_scan_details_url(scan_type, scan_id, scan_client), scan_id))
    responses_module.add(get_detection_rules_response(get_detection_rules_url(scan_client)))
    responses_module.add(get_scan_detections_response(get_scan_detections_url(scan_client), scan_id, zip_content_path))
    responses_module.add(get_report_scan_status_response(get_report_scan_status_url(scan_type, scan_id, scan_client)))
