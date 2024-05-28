import os
from uuid import uuid4

import pytest
import responses

from cycode.cli.commands.scan.code_scanner import (
    _try_get_aggregation_report_url_if_needed,
    _try_get_report_url_if_needed,
)
from cycode.cli.config import config
from cycode.cli.files_collector.excluder import _is_relevant_file_to_scan
from cycode.cyclient.scan_client import ScanClient
from tests.conftest import TEST_FILES_PATH
from tests.cyclient.mocked_responses.scan_client import (
    get_scan_aggregation_report_url,
    get_scan_aggregation_report_url_response,
    get_scan_report_url,
    get_scan_report_url_response,
)


def test_is_relevant_file_to_scan_sca() -> None:
    path = os.path.join(TEST_FILES_PATH, 'package.json')
    assert _is_relevant_file_to_scan('sca', path) is True


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
def test_try_get_report_url_if_needed_return_none(scan_type: str, scan_client: ScanClient) -> None:
    scan_id = uuid4().hex
    result = _try_get_report_url_if_needed(scan_client, False, scan_id, 'secret')
    assert result is None


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_try_get_report_url_if_needed_return_result(
    scan_type: str, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    scan_id = uuid4()
    url = get_scan_report_url(scan_id, scan_client, scan_type)
    responses.add(api_token_response)  # mock token based client
    responses.add(get_scan_report_url_response(url, scan_id))

    scan_report_url_response = scan_client.get_scan_report_url(str(scan_id), scan_type)
    result = _try_get_report_url_if_needed(scan_client, True, str(scan_id), scan_type)
    assert result == scan_report_url_response.report_url


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
def test_try_get_aggregation_report_url_if_no_report_command_needed_return_none(
    scan_type: str, scan_client: ScanClient
) -> None:
    aggregation_id = uuid4().hex
    scan_parameter = {'aggregation_id': aggregation_id}
    result = _try_get_aggregation_report_url_if_needed(scan_parameter, scan_client, scan_type)
    assert result is None


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
def test_try_get_aggregation_report_url_if_no_aggregation_id_needed_return_none(
    scan_type: str, scan_client: ScanClient
) -> None:
    scan_parameter = {'report': True}
    result = _try_get_aggregation_report_url_if_needed(scan_parameter, scan_client, scan_type)
    assert result is None


@pytest.mark.parametrize('scan_type', config['scans']['supported_scans'])
@responses.activate
def test_try_get_aggregation_report_url_if_needed_return_result(
    scan_type: str, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    aggregation_id = uuid4()
    scan_parameter = {'report': True, 'aggregation_id': aggregation_id}
    url = get_scan_aggregation_report_url(aggregation_id, scan_client, scan_type)
    responses.add(api_token_response)  # mock token based client
    responses.add(get_scan_aggregation_report_url_response(url, aggregation_id))

    scan_aggregation_report_url_response = scan_client.get_scan_aggregation_report_url(str(aggregation_id), scan_type)

    result = _try_get_aggregation_report_url_if_needed(scan_parameter, scan_client, scan_type)
    assert result == scan_aggregation_report_url_response.report_url
