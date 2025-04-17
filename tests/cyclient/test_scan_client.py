from uuid import uuid4

import pytest
import responses

from cycode.cli.cli_types import ScanTypeOption
from cycode.cyclient.scan_client import ScanClient
from tests.cyclient.mocked_responses.scan_client import (
    get_scan_aggregation_report_url,
    get_scan_aggregation_report_url_response,
)


@pytest.mark.parametrize('scan_type', list(ScanTypeOption))
@responses.activate
def test_get_scan_report_url(
    scan_type: ScanTypeOption, scan_client: ScanClient, api_token_response: responses.Response
) -> None:
    aggregation_id = uuid4()
    url = get_scan_aggregation_report_url(aggregation_id, scan_client, scan_type)

    responses.add(api_token_response)  # mock token based client
    responses.add(get_scan_aggregation_report_url_response(url, aggregation_id))

    scan_report_url_response = scan_client.get_scan_aggregation_report_url(str(aggregation_id), scan_type)
    assert scan_report_url_response.report_url == f'https://app.domain/cli-logs-aggregation/{aggregation_id}'
