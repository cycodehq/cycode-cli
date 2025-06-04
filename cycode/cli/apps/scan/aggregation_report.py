from typing import TYPE_CHECKING, Optional

import typer

from cycode.logger import get_logger

if TYPE_CHECKING:
    from cycode.cyclient.scan_client import ScanClient

logger = get_logger('Aggregation Report URL')


def _set_aggregation_report_url(ctx: typer.Context, aggregation_report_url: Optional[str] = None) -> None:
    ctx.obj['aggregation_report_url'] = aggregation_report_url


def try_get_aggregation_report_url_if_needed(
    scan_parameters: dict, cycode_client: 'ScanClient', scan_type: str
) -> Optional[str]:
    if not scan_parameters.get('report', False):
        return None

    aggregation_id = scan_parameters.get('aggregation_id')
    if aggregation_id is None:
        return None

    try:
        report_url_response = cycode_client.get_scan_aggregation_report_url(aggregation_id, scan_type)
        return report_url_response.report_url
    except Exception as e:
        logger.debug('Failed to get aggregation report url: %s', str(e))


def try_set_aggregation_report_url_if_needed(
    ctx: typer.Context, scan_parameters: dict, cycode_client: 'ScanClient', scan_type: str
) -> None:
    aggregation_report_url = try_get_aggregation_report_url_if_needed(scan_parameters, cycode_client, scan_type)
    if aggregation_report_url:
        _set_aggregation_report_url(ctx, aggregation_report_url)
        logger.debug('Aggregation report URL set successfully', {'aggregation_report_url': aggregation_report_url})
    else:
        logger.debug('No aggregation report URL found or report generation is disabled')
