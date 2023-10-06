import time

import click

from cycode.cli import consts
from cycode.cli.commands.report.sbom.common import create_sbom_report, send_report_feedback
from cycode.cli.commands.report.sbom.handle_errors import handle_report_exception
from cycode.cli.files_collector.path_documents import get_relevant_document
from cycode.cli.files_collector.sca.sca_code_scanner import perform_pre_scan_documents_actions
from cycode.cli.files_collector.zip_documents import zip_documents
from cycode.cli.utils.progress_bar import SbomReportProgressBarSection


@click.command(short_help='Generate SBOM report for provided path in the command.')
@click.argument('path', nargs=1, type=click.Path(exists=True, resolve_path=True), required=True)
@click.pass_context
def sbom_path_command(context: click.Context, path: str) -> None:
    client = context.obj['client']
    report_parameters = context.obj['report_parameters']
    output_format = report_parameters.output_format
    output_file = context.obj['output_file']

    progress_bar = context.obj['progress_bar']
    progress_bar.start()

    start_scan_time = time.time()
    report_execution_id = -1

    try:
        documents = get_relevant_document(
            progress_bar, SbomReportProgressBarSection.PREPARE_LOCAL_FILES, consts.SCA_SCAN_TYPE, path
        )
        # TODO(MarshalX): combine perform_pre_scan_documents_actions with get_relevant_document.
        #  unhardcode usage of context in perform_pre_scan_documents_actions
        perform_pre_scan_documents_actions(context, consts.SCA_SCAN_TYPE, documents)

        zipped_documents = zip_documents(consts.SCA_SCAN_TYPE, documents)
        report_execution = client.request_sbom_report_execution(report_parameters, zip_file=zipped_documents)
        report_execution_id = report_execution.id

        create_sbom_report(progress_bar, client, report_execution_id, output_file, output_format)

        send_report_feedback(
            client=client,
            start_scan_time=start_scan_time,
            report_type='SBOM',
            report_command_type='path',
            request_report_parameters=report_parameters.to_dict(without_entity_type=False),
            report_execution_id=report_execution_id,
            request_zip_file_size=zipped_documents.size,
        )
    except Exception as e:
        progress_bar.stop()

        send_report_feedback(
            client=client,
            start_scan_time=start_scan_time,
            report_type='SBOM',
            report_command_type='path',
            request_report_parameters=report_parameters.to_dict(without_entity_type=False),
            report_execution_id=report_execution_id,
            error_message=str(e),
        )

        handle_report_exception(context, e)
