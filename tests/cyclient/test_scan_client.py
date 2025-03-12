import os
from typing import List, Tuple
from uuid import uuid4

import pytest
import requests
import responses
from requests import Timeout
from requests.exceptions import ProxyError

from cycode.cli import consts
from cycode.cli.cli_types import ScanTypeOption
from cycode.cli.exceptions.custom_exceptions import (
    CycodeError,
    HttpUnauthorizedError,
    RequestConnectionError,
    RequestTimeout,
)
from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
from cycode.cli.files_collector.zip_documents import zip_documents
from cycode.cli.models import Document
from cycode.cyclient.scan_client import ScanClient
from tests.conftest import ZIP_CONTENT_PATH
from tests.cyclient.mocked_responses.scan_client import (
    get_scan_report_url,
    get_scan_report_url_response,
    get_zipped_file_scan_response,
    get_zipped_file_scan_url,
)


def zip_scan_resources(scan_type: ScanTypeOption, scan_client: ScanClient) -> Tuple[str, InMemoryZip]:
    url = get_zipped_file_scan_url(scan_type, scan_client)
    zip_file = get_test_zip_file(scan_type)

    return url, zip_file


def get_test_zip_file(scan_type: ScanTypeOption) -> InMemoryZip:
    # TODO(MarshalX): refactor scan_disk_files in code_scanner.py to reuse method here instead of this
    test_documents: List[Document] = []
    for root, _, files in os.walk(ZIP_CONTENT_PATH):
        for name in files:
            path = os.path.join(root, name)
            with open(path, 'r', encoding='UTF-8') as f:
                test_documents.append(Document(path, f.read(), is_git_diff_format=False))

    return zip_documents(scan_type, test_documents)


def test_get_service_name(scan_client: ScanClient) -> None:
    # TODO(MarshalX): get_service_name should be removed from ScanClient? Because it exists in ScanConfig
    assert scan_client.get_service_name(consts.SECRET_SCAN_TYPE) == 'secret'
    assert scan_client.get_service_name(consts.IAC_SCAN_TYPE) == 'iac'
    assert scan_client.get_service_name(consts.SCA_SCAN_TYPE) == 'scans'
    assert scan_client.get_service_name(consts.SAST_SCAN_TYPE) == 'scans'


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_zipped_file_scan(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    url, zip_file = zip_scan_resources(scan_type, scan_client)
    expected_scan_id = uuid4()

    responses.add(api_token_response)  # mock token based client
    responses.add(get_zipped_file_scan_response(url, ZIP_CONTENT_PATH, expected_scan_id))

    zipped_file_scan_response = scan_client.zipped_file_scan(
        scan_type, zip_file, scan_id=str(expected_scan_id), scan_parameters={}
    )
    assert zipped_file_scan_response.scan_id == str(expected_scan_id)


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_get_scan_report_url(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    scan_id = uuid4()
    url = get_scan_report_url(scan_id, scan_client, scan_type)

    responses.add(api_token_response)  # mock token based client
    responses.add(get_scan_report_url_response(url, scan_id))

    scan_report_url_response = scan_client.get_scan_report_url(str(scan_id), scan_type)
    assert scan_report_url_response.report_url == 'https://app.domain/on-demand-scans/{scan_id}'.format(scan_id=scan_id)


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_zipped_file_scan_unauthorized_error(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    url, zip_file = zip_scan_resources(scan_type, scan_client)
    expected_scan_id = uuid4().hex

    responses.add(api_token_response)  # mock token based client
    responses.add(method=responses.POST, url=url, status=401)

    with pytest.raises(HttpUnauthorizedError) as e_info:
        scan_client.zipped_file_scan(scan_type, zip_file, scan_id=expected_scan_id, scan_parameters={})

    assert e_info.value.status_code == 401


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_zipped_file_scan_bad_request_error(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    url, zip_file = zip_scan_resources(scan_type, scan_client)
    expected_scan_id = uuid4().hex

    expected_status_code = 400
    expected_response_text = 'Bad Request'

    responses.add(api_token_response)  # mock token based client
    responses.add(method=responses.POST, url=url, status=expected_status_code, body=expected_response_text)

    with pytest.raises(CycodeError) as e_info:
        scan_client.zipped_file_scan(scan_type, zip_file, scan_id=expected_scan_id, scan_parameters={})

    assert e_info.value.status_code == expected_status_code
    assert e_info.value.error_message == expected_response_text


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_zipped_file_scan_timeout_error(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    scan_url, zip_file = zip_scan_resources(scan_type, scan_client)
    expected_scan_id = uuid4().hex

    responses.add(responses.POST, scan_url, status=504)

    timeout_response = requests.post(scan_url, timeout=5)
    if timeout_response.status_code == 504:
        """bypass SAST"""

    responses.reset()

    timeout_error = Timeout()
    timeout_error.response = timeout_response

    responses.add(api_token_response)  # mock token based client
    responses.add(method=responses.POST, url=scan_url, body=timeout_error, status=504)

    with pytest.raises(RequestTimeout):
        scan_client.zipped_file_scan(scan_type, zip_file, scan_id=expected_scan_id, scan_parameters={})


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_zipped_file_scan_connection_error(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    url, zip_file = zip_scan_resources(scan_type, scan_client)
    expected_scan_id = uuid4().hex

    responses.add(api_token_response)  # mock token based client
    responses.add(method=responses.POST, url=url, body=ProxyError())

    with pytest.raises(RequestConnectionError):
        scan_client.zipped_file_scan(scan_type, zip_file, scan_id=expected_scan_id, scan_parameters={})
