import os
from pathlib import Path
from uuid import uuid4

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
from cyclient.scan_config.scan_config_creator import create_scan_client

_CLIENT_ID = 'b1234568-0eaa-1234-beb8-6f0c12345678'
_CLIENT_SECRET = 'a12345a-42b2-1234-3bdd-c0130123456'

_TEST_FILES_PATH = Path(__file__).parent.parent.joinpath('test_files', 'zip_content').absolute()


@pytest.fixture(scope='module', name='client')
def scan_client() -> ScanClient:
    return create_scan_client(_CLIENT_ID, _CLIENT_SECRET)


def zip_scan_resources(scan_type: str, client: ScanClient):
    url = get_zipped_file_scan_url(scan_type, client)
    zip_file = get_test_zip_file(scan_type)

    return url, zip_file


def get_zipped_file_scan_url(scan_type: str, client: ScanClient) -> str:
    api_url = client.scan_cycode_client.api_url
    # TODO(MarshalX): create method in the scan client to build this url
    return f'{api_url}/{client.scan_config.get_service_name(scan_type)}/{client.SCAN_CONTROLLER_PATH}/zipped-file'


def get_test_zip_file(scan_type: str) -> InMemoryZip:
    # TODO(MarshalX): refactor scan_disk_files in code_scanner.py to reuse method here instead of this
    test_documents: List[Document] = []
    for root, _, files in os.walk(_TEST_FILES_PATH):
        for name in files:
            path = os.path.join(root, name)
            with open(path, 'r', encoding='UTF-8') as f:
                test_documents.append(Document(path, f.read(), is_git_diff_format=False))

    return zip_documents_to_scan(scan_type, InMemoryZip(), test_documents)


def test_get_service_name(client: ScanClient):
    # TODO(Marshal): get_service_name should be removed from ScanClient? Because it exists in ScanConfig
    assert client.get_service_name('secret') == 'secret'
    assert client.get_service_name('iac') == 'iac'
    assert client.get_service_name('sca') == 'scans'
    assert client.get_service_name('sast') == 'scans'


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_zipped_file_scan(scan_type: str, client: ScanClient, api_token_response):
    url, zip_file = zip_scan_resources(scan_type, client)
    excepted_scan_id = uuid4()

    json_response = {
        "did_detect": True,
        "scan_id": excepted_scan_id.hex,
        "detections_per_file": [
            {
                "file_name": "/Users/.../cycode-cli/tests/test_files/zip_content/secrets.py",
                "commit_id": None,
                "detections": [
                    {
                        "detection_type_id": "12345678-418f-47ee-abb0-012345678901",
                        "detection_rule_id": "12345678-aea1-4304-a6e9-012345678901",
                        "message": "Secret of type 'Slack Token' was found in filename 'secrets.py' within '' repository",
                        "type": "slack-token",
                        "is_research": False,
                        "detection_details": {
                            "sha512": "sha hash",
                            "length": 55,
                            "start_position": 19,
                            "line": 0,
                            "committed_at": "0001-01-01T00:00:00+00:00",
                            "file_path": "/Users/.../cycode-cli/tests/test_files/zip_content/",
                            "file_name": "secrets.py",
                            "file_extension": ".py",
                            "should_resolve_upon_branch_deletion": False
                        }
                    }
                ]
            }
        ],
        "report_url": None
    }

    responses.add(api_token_response)   # mock token based client
    responses.add(method=responses.POST, url=url, json=json_response, status=200)

    # TODO(MarshalX): fix wrong type hint? UUID instead of str
    zipped_file_scan_response = client.zipped_file_scan(
        scan_type, zip_file, scan_id=excepted_scan_id, scan_parameters={}
    )
    assert zipped_file_scan_response.scan_id == excepted_scan_id.hex


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_zipped_file_scan_unauthorized_error(scan_type: str, client: ScanClient, api_token_response):
    url, zip_file = zip_scan_resources(scan_type, client)
    excepted_scan_id = uuid4().hex

    responses.add(api_token_response)   # mock token based client
    responses.add(method=responses.POST, url=url, status=401)

    with pytest.raises(HttpUnauthorizedError) as e_info:
        client.zipped_file_scan(scan_type, zip_file, scan_id=excepted_scan_id, scan_parameters={})

    assert e_info.value.status_code == 401


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_zipped_file_scan_bad_request_error(scan_type: str, client: ScanClient, api_token_response):
    url, zip_file = zip_scan_resources(scan_type, client)
    excepted_scan_id = uuid4().hex

    excepted_status_code = 400
    excepted_response_text = 'Bad Request'

    responses.add(api_token_response)   # mock token based client
    responses.add(method=responses.POST, url=url, status=excepted_status_code, body=excepted_response_text)

    with pytest.raises(CycodeError) as e_info:
        client.zipped_file_scan(scan_type, zip_file, scan_id=excepted_scan_id, scan_parameters={})

    assert e_info.value.status_code == excepted_status_code
    assert e_info.value.error_message == excepted_response_text


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_zipped_file_scan_timeout_error(scan_type: str, client: ScanClient, api_token_response):
    url, zip_file = zip_scan_resources(scan_type, client)
    excepted_scan_id = uuid4().hex

    excepted_status_code = 504

    responses.add(responses.POST, url, status=excepted_status_code)
    timeout_response = requests.post(url)
    responses.reset()

    timeout_error = Timeout()
    timeout_error.response = timeout_response

    responses.add(api_token_response)   # mock token based client
    responses.add(method=responses.POST, url=url, body=timeout_error, status=504)

    with pytest.raises(CycodeError) as e_info:
        client.zipped_file_scan(scan_type, zip_file, scan_id=excepted_scan_id, scan_parameters={})

    assert e_info.value.status_code == excepted_status_code
    assert e_info.value.error_message == 'Timeout Error'


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_zipped_file_scan_connection_error(scan_type: str, client: ScanClient, api_token_response):
    url, zip_file = zip_scan_resources(scan_type, client)
    excepted_scan_id = uuid4().hex

    responses.add(api_token_response)   # mock token based client
    responses.add(method=responses.POST, url=url, body=ProxyError())

    with pytest.raises(CycodeError) as e_info:
        client.zipped_file_scan(scan_type, zip_file, scan_id=excepted_scan_id, scan_parameters={})

    assert e_info.value.status_code == 502
    assert e_info.value.error_message == 'Connection Error'
