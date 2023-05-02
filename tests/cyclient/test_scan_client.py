import os
from uuid import uuid4, UUID

import pytest
import requests
import responses
from typing import List

from requests import Timeout
from requests.exceptions import ProxyError

from cli.config import config
from cli.zip_file import InMemoryZip
from cli.models import Document
from cli.code_scanner import zip_documents_to_scan
from cli.exceptions.custom_exceptions import HttpUnauthorizedError, CycodeError
from cyclient.scan_client import ScanClient
from tests.conftest import TEST_FILES_PATH


_ZIP_CONTENT_PATH = TEST_FILES_PATH.joinpath('zip_content').absolute()


def zip_scan_resources(scan_type: str, scan_client: ScanClient):
    url = get_zipped_file_scan_url(scan_type, scan_client)
    zip_file = get_test_zip_file(scan_type)

    return url, zip_file


def get_zipped_file_scan_url(scan_type: str, scan_client: ScanClient) -> str:
    api_url = scan_client.scan_cycode_client.api_url
    # TODO(MarshalX): create method in the scan client to build this url
    return f'{api_url}/{scan_client.scan_config.get_service_name(scan_type)}/{scan_client.SCAN_CONTROLLER_PATH}/zipped-file'


def get_test_zip_file(scan_type: str) -> InMemoryZip:
    # TODO(MarshalX): refactor scan_disk_files in code_scanner.py to reuse method here instead of this
    test_documents: List[Document] = []
    for root, _, files in os.walk(_ZIP_CONTENT_PATH):
        for name in files:
            path = os.path.join(root, name)
            with open(path, 'r', encoding='UTF-8') as f:
                test_documents.append(Document(path, f.read(), is_git_diff_format=False))

    return zip_documents_to_scan(scan_type, InMemoryZip(), test_documents)


def get_zipped_file_scan_response(url: str, scan_id: UUID = None) -> responses.Response:
    if not scan_id:
        scan_id = uuid4()

    json_response = {
        'did_detect': True,
        'scan_id': scan_id.hex,     # not always as expected due to _get_scan_id and passing scan_id to cxt of CLI
        'detections_per_file': [
            {
                'file_name': str(_ZIP_CONTENT_PATH.joinpath('secrets.py')),
                'commit_id': None,
                'detections': [
                    {
                        'detection_type_id': '12345678-418f-47ee-abb0-012345678901',
                        'detection_rule_id': '12345678-aea1-4304-a6e9-012345678901',
                        'message': "Secret of type 'Slack Token' was found in filename 'secrets.py'",
                        'type': 'slack-token',
                        'is_research': False,
                        'detection_details': {
                            'sha512': 'sha hash',
                            'length': 55,
                            'start_position': 19,
                            'line': 0,
                            'committed_at': '0001-01-01T00:00:00+00:00',
                            'file_path': str(_ZIP_CONTENT_PATH),
                            'file_name': 'secrets.py',
                            'file_extension': '.py',
                            'should_resolve_upon_branch_deletion': False
                        }
                    }
                ]
            }
        ],
        'report_url': None
    }

    return responses.Response(method=responses.POST, url=url, json=json_response, status=200)


def test_get_service_name(scan_client: ScanClient):
    # TODO(Marshal): get_service_name should be removed from ScanClient? Because it exists in ScanConfig
    assert scan_client.get_service_name('secret') == 'secret'
    assert scan_client.get_service_name('iac') == 'iac'
    assert scan_client.get_service_name('sca') == 'scans'
    assert scan_client.get_service_name('sast') == 'scans'


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_zipped_file_scan(scan_type: str, scan_client: ScanClient, api_token_response):
    url, zip_file = zip_scan_resources(scan_type, scan_client)
    expected_scan_id = uuid4()

    responses.add(api_token_response)   # mock token based client
    responses.add(get_zipped_file_scan_response(url, expected_scan_id))

    # TODO(MarshalX): fix wrong type hint? UUID instead of str
    zipped_file_scan_response = scan_client.zipped_file_scan(
        scan_type, zip_file, scan_id=expected_scan_id, scan_parameters={}
    )
    assert zipped_file_scan_response.scan_id == expected_scan_id.hex


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_zipped_file_scan_unauthorized_error(scan_type: str, scan_client: ScanClient, api_token_response):
    url, zip_file = zip_scan_resources(scan_type, scan_client)
    expected_scan_id = uuid4().hex

    responses.add(api_token_response)   # mock token based client
    responses.add(method=responses.POST, url=url, status=401)

    with pytest.raises(HttpUnauthorizedError) as e_info:
        scan_client.zipped_file_scan(scan_type, zip_file, scan_id=expected_scan_id, scan_parameters={})

    assert e_info.value.status_code == 401


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_zipped_file_scan_bad_request_error(scan_type: str, scan_client: ScanClient, api_token_response):
    url, zip_file = zip_scan_resources(scan_type, scan_client)
    expected_scan_id = uuid4().hex

    expected_status_code = 400
    expected_response_text = 'Bad Request'

    responses.add(api_token_response)   # mock token based client
    responses.add(method=responses.POST, url=url, status=expected_status_code, body=expected_response_text)

    with pytest.raises(CycodeError) as e_info:
        scan_client.zipped_file_scan(scan_type, zip_file, scan_id=expected_scan_id, scan_parameters={})

    assert e_info.value.status_code == expected_status_code
    assert e_info.value.error_message == expected_response_text


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_zipped_file_scan_timeout_error(scan_type: str, scan_client: ScanClient, api_token_response):
    scan_url, zip_file = zip_scan_resources(scan_type, scan_client)
    expected_scan_id = uuid4().hex

    responses.add(responses.POST, scan_url, status=504)

    timeout_response = requests.post(scan_url, timeout=5)
    if timeout_response.status_code == 504:
        """bypass SAST"""

    responses.reset()

    timeout_error = Timeout()
    timeout_error.response = timeout_response

    responses.add(api_token_response)   # mock token based client
    responses.add(method=responses.POST, url=scan_url, body=timeout_error, status=504)

    with pytest.raises(CycodeError) as e_info:
        scan_client.zipped_file_scan(scan_type, zip_file, scan_id=expected_scan_id, scan_parameters={})

    assert e_info.value.status_code == 504
    assert e_info.value.error_message == 'Timeout Error'


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_zipped_file_scan_connection_error(scan_type: str, scan_client: ScanClient, api_token_response):
    url, zip_file = zip_scan_resources(scan_type, scan_client)
    expected_scan_id = uuid4().hex

    responses.add(api_token_response)   # mock token based client
    responses.add(method=responses.POST, url=url, body=ProxyError())

    with pytest.raises(CycodeError) as e_info:
        scan_client.zipped_file_scan(scan_type, zip_file, scan_id=expected_scan_id, scan_parameters={})

    assert e_info.value.status_code == 502
    assert e_info.value.error_message == 'Connection Error'
