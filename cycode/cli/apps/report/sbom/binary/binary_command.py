import time
from pathlib import Path
from typing import Annotated

import typer

from cycode.cli import consts
from cycode.cli.apps.report.sbom.common import create_sbom_report, send_report_feedback
from cycode.cli.exceptions.handle_report_sbom_errors import handle_report_exception
from cycode.cli.files_collector.binary.collector import collect_binary_documents
from cycode.cli.files_collector.zip_documents import zip_documents
from cycode.cli.utils.get_api_client import get_report_cycode_client
from cycode.cli.utils.progress_bar import SbomReportProgressBarSection

_REPORT_COMMAND_TYPE = 'binary'


def binary_command(
    ctx: typer.Context,
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            resolve_path=True,
            help='Path to the built artifact to generate an SBOM for.',
            show_default=False,
        ),
    ],
    max_depth: Annotated[
        int,
        typer.Option('--max-depth', help='Nested-archive recursion limit.', min=1),
    ] = consts.BINARY_MAX_DEPTH,
    maven_central: Annotated[
        bool,
        typer.Option(
            '--maven-central',
            help='Look archives that embedded metadata cannot identify up on Maven Central by SHA-1. '
            'Sends the digest of each such archive, never the archive itself, to search.maven.org.',
        ),
    ] = False,
) -> None:
    """:package: [bold cyan]Generate an SBOM for a built Java artifact.[/]

    Reads a JAR, WAR, EAR or Spring Boot fat JAR and produces an SBOM of the open-source components inside it,
    without scanning them for vulnerabilities. Answers the compliance case directly: an SBOM of what shipped,
    rather than of what was committed.

    Example usage:
    * `cycode report sbom --format cyclonedx-1.4-json binary app.war`
    * `cycode report sbom --format spdx-2.3-json binary app.ear`

    Format conversion happens server-side, so every format the path command supports is supported here too.

    """
    ctx.obj['binary_max_depth'] = max_depth
    ctx.obj['maven_central'] = maven_central

    client = get_report_cycode_client(ctx)
    report_parameters = ctx.obj['report_parameters']
    output_format = report_parameters.output_format
    output_file = ctx.obj['output_file']

    progress_bar = ctx.obj['progress_bar']
    progress_bar.start()

    start_scan_time = time.time()
    report_execution_id = -1

    try:
        # the only difference from the path command: our collector in place of the manifest walk. Everything from
        # zip_documents onward is reused verbatim, and the server generates the document.
        collection = collect_binary_documents(
            ctx,
            (str(path),),
            stop_on_error=ctx.obj.get('stop_on_error', False),
            progress_bar_section=SbomReportProgressBarSection.PREPARE_LOCAL_FILES,
        )
        ctx.obj['binary_result'] = collection

        if not collection.documents:
            raise typer.BadParameter(
                f'No supported binary artifacts were found at {str(path)!r}. '
                'Supported artifacts are .jar, .war and .ear files.',
                param_hint='PATH',
            )

        zipped_documents = zip_documents(consts.SCA_SCAN_TYPE, collection.documents)
        report_execution = client.request_sbom_report_execution(report_parameters, zip_file=zipped_documents)
        report_execution_id = report_execution.id

        create_sbom_report(progress_bar, client, report_execution_id, output_file, output_format)

        send_report_feedback(
            client=client,
            start_scan_time=start_scan_time,
            report_type='SBOM',
            report_command_type=_REPORT_COMMAND_TYPE,
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
            report_command_type=_REPORT_COMMAND_TYPE,
            request_report_parameters=report_parameters.to_dict(without_entity_type=False),
            report_execution_id=report_execution_id,
            error_message=str(e),
        )

        handle_report_exception(ctx, e)
