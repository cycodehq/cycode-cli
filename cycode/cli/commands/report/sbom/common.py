import time
from typing import TYPE_CHECKING

import click

if TYPE_CHECKING:
    from cycode.cyclient.report_client import ReportClient


def create_sbom_report(client: 'ReportClient', report_id: int, output_file: str) -> None:
    # TODO(MarshalX): API will be changed soon. Just MVP for now.
    report_satus = None
    status = 'Running'
    while status == 'Running':
        report_satus = client.get_execution_status(report_id)[0]
        status = report_satus.report_executions[0].status
        time.sleep(3)

    if not report_satus:
        raise click.ClickException('Failed to get report status.')

    report_path = report_satus.report_executions[0].storage_details.path
    report_content = client.get_file_content(report_path)
    with open(output_file, 'w', encoding='UTF-8') as f:
        f.write(report_content)
