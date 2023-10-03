import pathlib
import time
from platform import platform
from typing import TYPE_CHECKING, Optional

from cycode.cli import consts
from cycode.cli.commands.report.sbom.sbom_report_file import SbomReportFile
from cycode.cli.config import configuration_manager
from cycode.cli.exceptions.custom_exceptions import ReportAsyncError
from cycode.cli.utils.progress_bar import SbomReportProgressBarSection
from cycode.cyclient import logger
from cycode.cyclient.models import ReportExecutionSchema

if TYPE_CHECKING:
    from cycode.cli.utils.progress_bar import BaseProgressBar
    from cycode.cyclient.report_client import ReportClient


def _poll_report_execution_until_completed(
    progress_bar: 'BaseProgressBar',
    client: 'ReportClient',
    report_execution_id: int,
    polling_timeout: Optional[int] = None,
) -> ReportExecutionSchema:
    if polling_timeout is None:
        polling_timeout = configuration_manager.get_report_polling_timeout_in_seconds()

    end_polling_time = time.time() + polling_timeout
    while time.time() < end_polling_time:
        report_execution = client.get_report_execution(report_execution_id)
        report_label = report_execution.error_message or report_execution.status_message

        progress_bar.update_label(report_label)

        if report_execution.status == consts.REPORT_STATUS_COMPLETED:
            return report_execution

        if report_execution.status == consts.REPORT_STATUS_ERROR:
            raise ReportAsyncError(f'Error occurred while trying to generate report: {report_label}')

        time.sleep(consts.REPORT_POLLING_WAIT_INTERVAL_IN_SECONDS)

    raise ReportAsyncError(f'Timeout exceeded while waiting for report to complete. Timeout: {polling_timeout} sec.')


def send_report_feedback(
    client: 'ReportClient',
    start_scan_time: float,
    report_type: str,
    report_command_type: str,
    request_report_parameters: dict,
    report_execution_id: int,
    error_message: Optional[str] = None,
    request_zip_file_size: Optional[int] = None,
    **kwargs,
) -> None:
    try:
        request_report_parameters.update(kwargs)

        end_scan_time = time.time()
        scan_status = {
            'report_type': report_type,
            'report_command_type': report_command_type,
            'request_report_parameters': request_report_parameters,
            'operation_system': platform(),
            'error_message': error_message,
            'execution_time': int(end_scan_time - start_scan_time),
            'request_zip_file_size': request_zip_file_size,
        }

        client.report_status(report_execution_id, scan_status)
    except Exception as e:
        logger.debug(f'Failed to send report feedback: {e}')


def create_sbom_report(
    progress_bar: 'BaseProgressBar',
    client: 'ReportClient',
    report_execution_id: int,
    output_file: Optional[pathlib.Path],
    output_format: str,
) -> None:
    report_execution = _poll_report_execution_until_completed(progress_bar, client, report_execution_id)

    progress_bar.set_section_length(SbomReportProgressBarSection.GENERATION)

    report_path = report_execution.storage_details.path
    report_content = client.get_file_content(report_path)

    progress_bar.set_section_length(SbomReportProgressBarSection.RECEIVE_REPORT)
    progress_bar.stop()

    sbom_report = SbomReportFile(report_path, output_format, output_file)
    sbom_report.write(report_content)
