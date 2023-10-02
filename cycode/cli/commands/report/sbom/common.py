import pathlib
import time
from typing import TYPE_CHECKING, Optional

from cycode.cli.commands.report.sbom.sbom_report_file import SbomReportFile
from cycode.cli.utils.progress_bar import SbomReportProgressBarSection

if TYPE_CHECKING:
    from cycode.cli.utils.progress_bar import BaseProgressBar
    from cycode.cyclient.report_client import ReportClient


def create_sbom_report(
    progress_bar: 'BaseProgressBar',
    client: 'ReportClient',
    report_execution_id: int,
    output_file: Optional[pathlib.Path],
    output_format: str,
) -> None:
    report_execution = client.get_report_execution(report_execution_id)
    while report_execution.status == 'Running':
        time.sleep(3)

        report_execution = client.get_report_execution(report_execution_id)
        report_label = report_execution.error_message or report_execution.status_message
        progress_bar.update_label(report_label)

    progress_bar.set_section_length(SbomReportProgressBarSection.GENERATION)

    report_path = report_execution.storage_details.path
    report_content = client.get_file_content(report_path)

    progress_bar.set_section_length(SbomReportProgressBarSection.RECEIVE_REPORT)
    progress_bar.stop()

    sbom_report = SbomReportFile(report_path, output_format, output_file)
    sbom_report.write(report_content)
