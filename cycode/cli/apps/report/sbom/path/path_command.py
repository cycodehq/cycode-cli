import time
from pathlib import Path
from typing import Annotated

import typer

from cycode.cli import consts
from cycode.cli.apps.report.sbom.common import create_sbom_report, send_report_feedback
from cycode.cli.exceptions.handle_report_sbom_errors import handle_report_exception
from cycode.cli.files_collector.path_documents import get_relevant_documents
from cycode.cli.files_collector.sca.sca_file_collector import add_sca_dependencies_tree_documents_if_needed
from cycode.cli.files_collector.zip_documents import zip_documents
from cycode.cli.utils.get_api_client import get_report_cycode_client
from cycode.cli.utils.progress_bar import SbomReportProgressBarSection
from cycode.cli.utils.sentry import add_breadcrumb


def path_command(
    ctx: typer.Context,
    path: Annotated[
        Path,
        typer.Argument(exists=True, resolve_path=True, help='Path to generate SBOM report for.', show_default=False),
    ],
) -> None:
    add_breadcrumb('path')

    client = get_report_cycode_client(ctx)
    report_parameters = ctx.obj['report_parameters']
    output_format = report_parameters.output_format
    output_file = ctx.obj['output_file']

    progress_bar = ctx.obj['progress_bar']
    progress_bar.start()

    start_scan_time = time.time()
    report_execution_id = -1

    try:
        documents = get_relevant_documents(
            progress_bar, SbomReportProgressBarSection.PREPARE_LOCAL_FILES, consts.SCA_SCAN_TYPE, (str(path),)
        )
        # TODO(MarshalX): combine perform_pre_scan_documents_actions with get_relevant_document.
        #  unhardcode usage of context in perform_pre_scan_documents_actions
        add_sca_dependencies_tree_documents_if_needed(ctx, consts.SCA_SCAN_TYPE, documents)

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

        handle_report_exception(ctx, e)
