import pathlib
import time
from typing import TYPE_CHECKING, Optional

import click

from cycode.cli.commands.report.sbom.sbom_report_file import SbomReportFile
from cycode.cli.utils.progress_bar import SbomReportProgressBarSection

if TYPE_CHECKING:
    from cycode.cli.utils.progress_bar import BaseProgressBar
    from cycode.cyclient.report_client import ReportClient


def create_sbom_report(
    progress_bar: 'BaseProgressBar',
    client: 'ReportClient',
    report_id: int,
    output_file: Optional[pathlib.Path],
    output_format: str,
) -> None:
    # TODO(MarshalX): API will be changed soon. Just MVP for now.
    report_satus = None
    status = 'Running'
    while status == 'Running':
        report_satus = client.get_execution_status(report_id)[0]
        execution = report_satus.report_executions[0]

        status = execution.status

        progress_bar.update_label(execution.error_message or execution.status_message)
        time.sleep(3)

    if not report_satus:
        raise click.ClickException('Failed to get report status.')

    progress_bar.set_section_length(SbomReportProgressBarSection.GENERATION)

    report_path = report_satus.report_executions[0].storage_details.path
    report_content = client.get_file_content(report_path)

    progress_bar.set_section_length(SbomReportProgressBarSection.RECEIVE_REPORT)
    progress_bar.stop()

    sbom_report = SbomReportFile(report_path, output_format, output_file)
    sbom_report.write(report_content)
