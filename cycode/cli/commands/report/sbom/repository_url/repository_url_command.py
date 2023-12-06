import time

import click

from cycode.cli.commands.report.sbom.common import create_sbom_report, send_report_feedback
from cycode.cli.exceptions.handle_report_sbom_errors import handle_report_exception
from cycode.cli.utils.get_api_client import get_report_cycode_client
from cycode.cli.utils.progress_bar import SbomReportProgressBarSection


@click.command(short_help='Generate SBOM report for provided repository URI in the command.')
@click.argument('uri', nargs=1, type=str, required=True)
@click.pass_context
def repository_url_command(context: click.Context, uri: str) -> None:
    progress_bar = context.obj['progress_bar']
    progress_bar.start()
    progress_bar.set_section_length(SbomReportProgressBarSection.PREPARE_LOCAL_FILES)

    client = get_report_cycode_client()
    report_parameters = context.obj['report_parameters']
    output_file = context.obj['output_file']
    output_format = report_parameters.output_format

    start_scan_time = time.time()
    report_execution_id = -1

    try:
        report_execution = client.request_sbom_report_execution(report_parameters, repository_url=uri)
        report_execution_id = report_execution.id

        create_sbom_report(progress_bar, client, report_execution_id, output_file, output_format)

        send_report_feedback(
            client=client,
            start_scan_time=start_scan_time,
            report_type='SBOM',
            report_command_type='repository_url',
            request_report_parameters=report_parameters.to_dict(without_entity_type=False),
            report_execution_id=report_execution_id,
            repository_uri=uri,
        )
    except Exception as e:
        progress_bar.stop()

        send_report_feedback(
            client=client,
            start_scan_time=start_scan_time,
            report_type='SBOM',
            report_command_type='repository_url',
            request_report_parameters=report_parameters.to_dict(without_entity_type=False),
            report_execution_id=report_execution_id,
            error_message=str(e),
            repository_uri=uri,
        )

        handle_report_exception(context, e)
