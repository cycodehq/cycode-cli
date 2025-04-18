import os
from typing import List, Tuple
from uuid import uuid4

import pytest
import requests
import responses
from requests.exceptions import ConnectionError as RequestsConnectionError

from cycode.cli.cli_types import ScanTypeOption
from cycode.cli.exceptions.custom_exceptions import (
    CycodeError,
    HttpUnauthorizedError,
    RequestConnectionError,
    RequestTimeout,
)
from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip
from cycode.cli.models import Document
from cycode.cyclient.scan_client import ScanClient
from tests.conftest import ZIP_CONTENT_PATH
from tests.cyclient.mocked_responses.scan_client import (
    get_scan_aggregation_report_url,
    get_scan_aggregation_report_url_response,
    get_scan_details_response,
    get_scan_details_url,
    get_zipped_file_scan_async_response,
    get_zipped_file_scan_async_url,
)


def zip_scan_resources(scan_type: ScanTypeOption, scan_client: ScanClient) -> Tuple[str, InMemoryZip]:
    url = get_zipped_file_scan_async_url(scan_type, scan_client)
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

    from cycode.cli.files_collector.zip_documents import zip_documents

    return zip_documents(scan_type, test_documents)


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_zipped_file_scan_async(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    """Test the zipped_file_scan_async method for the async flow."""
    url, zip_file = zip_scan_resources(scan_type, scan_client)
    expected_scan_id = uuid4()

    responses.add(api_token_response)  # mock token based client
    responses.add(get_zipped_file_scan_async_response(url, expected_scan_id))

    scan_initialization_response = scan_client.zipped_file_scan_async(zip_file, scan_type, scan_parameters={})
    assert scan_initialization_response.scan_id == str(expected_scan_id)


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_get_scan_report_url(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    """Test getting the scan report URL for the async flow."""
    scan_id = uuid4()
    url = get_scan_aggregation_report_url(scan_id, scan_client, scan_type)

    responses.add(api_token_response)  # mock token based client
    responses.add(get_scan_aggregation_report_url_response(url, scan_id))

    scan_report_url_response = scan_client.get_scan_aggregation_report_url(str(scan_id), scan_type)
    assert scan_report_url_response.report_url == f'https://app.domain/cli-logs-aggregation/{scan_id}'


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_zipped_file_scan_async_unauthorized_error(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    """Test handling of unauthorized errors in the async flow."""
    url, zip_file = zip_scan_resources(scan_type, scan_client)

    responses.add(api_token_response)  # mock token based client
    responses.add(method=responses.POST, url=url, status=401, body='Unauthorized')

    with pytest.raises(HttpUnauthorizedError) as e_info:
        scan_client.zipped_file_scan_async(zip_file=zip_file, scan_type=scan_type, scan_parameters={})

    assert e_info.value.status_code == 401


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_zipped_file_scan_async_bad_request_error(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    """Test handling of bad request errors in the async flow."""
    url, zip_file = zip_scan_resources(scan_type, scan_client)

    expected_status_code = 400
    expected_response_text = 'Bad Request'

    responses.add(api_token_response)  # mock token based client
    responses.add(method=responses.POST, url=url, status=expected_status_code, body=expected_response_text)

    with pytest.raises(CycodeError) as e_info:
        scan_client.zipped_file_scan_async(zip_file=zip_file, scan_type=scan_type, scan_parameters={})

    assert e_info.value.status_code == expected_status_code
    assert e_info.value.error_message == expected_response_text


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_zipped_file_scan_async_timeout_error(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    """Test handling of timeout errors in the async flow."""
    url, zip_file = zip_scan_resources(scan_type, scan_client)

    timeout_error = requests.exceptions.Timeout('Connection timed out')

    responses.add(api_token_response)  # mock token based client
    responses.add(method=responses.POST, url=url, body=timeout_error)

    with pytest.raises(RequestTimeout):
        scan_client.zipped_file_scan_async(zip_file=zip_file, scan_type=scan_type, scan_parameters={})


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_zipped_file_scan_async_connection_error(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    """Test handling of connection errors in the async flow."""
    url, zip_file = zip_scan_resources(scan_type, scan_client)

    # Create a connection error response
    connection_error = RequestsConnectionError('Connection refused')

    responses.add(api_token_response)  # mock token based client
    responses.add(method=responses.POST, url=url, body=connection_error)

    with pytest.raises(RequestConnectionError):
        scan_client.zipped_file_scan_async(zip_file=zip_file, scan_type=scan_type, scan_parameters={})


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_get_scan_details(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    """Test getting scan details in the async flow."""
    scan_id = uuid4()
    url = get_scan_details_url(scan_type, scan_id, scan_client)

    responses.add(api_token_response)  # mock token based client
    responses.add(get_scan_details_response(url, scan_id))

    scan_details_response = scan_client.get_scan_details(scan_type, str(scan_id))
    assert scan_details_response.id == str(scan_id)
    assert scan_details_response.scan_status == 'Completed'
