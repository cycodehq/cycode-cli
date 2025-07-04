import os
from uuid import uuid4

import pytest
import responses

from cycode.cli import consts
from cycode.cli.apps.scan.aggregation_report import try_get_aggregation_report_url_if_needed
from cycode.cli.cli_types import ScanTypeOption
from cycode.cli.files_collector.file_excluder import excluder
from cycode.cyclient.scan_client import ScanClient
from tests.conftest import TEST_FILES_PATH
from tests.cyclient.mocked_responses.scan_client import (
    get_scan_aggregation_report_url,
    get_scan_aggregation_report_url_response,
)


def test_is_relevant_file_to_scan_sca() -> None:
    path = os.path.join(TEST_FILES_PATH, 'package.json')
    assert excluder._is_relevant_file_to_scan(consts.SCA_SCAN_TYPE, path) is True


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
def test_try_get_aggregation_report_url_if_no_report_command_needed_return_none(
    scan_type: ScanTypeOption, scan_client: ScanClient
) -> None:
    aggregation_id = uuid4().hex
    scan_parameter = {'aggregation_id': aggregation_id}
    result = try_get_aggregation_report_url_if_needed(scan_parameter, scan_client, scan_type)
    assert result is None


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
def test_try_get_aggregation_report_url_if_no_aggregation_id_needed_return_none(
    scan_type: ScanTypeOption, scan_client: ScanClient
) -> None:
    scan_parameter = {'report': True}
    result = try_get_aggregation_report_url_if_needed(scan_parameter, scan_client, scan_type)
    assert result is None


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_try_get_aggregation_report_url_if_needed_return_result(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    aggregation_id = uuid4()
    scan_parameter = {'report': True, 'aggregation_id': aggregation_id}
    url = get_scan_aggregation_report_url(aggregation_id, scan_client, scan_type)
    responses.add(api_token_response)  # mock token based client
    responses.add(get_scan_aggregation_report_url_response(url, aggregation_id))

    scan_aggregation_report_url_response = scan_client.get_scan_aggregation_report_url(str(aggregation_id), scan_type)

    result = try_get_aggregation_report_url_if_needed(scan_parameter, scan_client, scan_type)
    assert result == scan_aggregation_report_url_response.report_url
