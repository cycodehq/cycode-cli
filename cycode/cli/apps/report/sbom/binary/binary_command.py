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
            help='Consult Maven Central: look archives that embedded metadata cannot identify up by SHA-1, and '
            'with --include-declared fetch parent poms to pin declared versions. Sends digests and public '
            'coordinates, never the archive itself.',
        ),
    ] = False,
    include_declared: Annotated[
        bool,
        typer.Option(
            '--include-declared',
            help='Also include the compile- and runtime-scope dependencies that embedded pom.xml files declare '
            'but the artifact does not ship, marked as declared rather than shipped. '
            'Versions managed by a parent pom need --maven-central to resolve.',
        ),
    ] = False,
    include_test_scope: Annotated[
        bool,
        typer.Option(
            '--include-test-scope',
            help='With --include-declared: also include test-, provided- and system-scope declarations, which '
            'Maven never passes to a consuming build. Each component still records its scope.',
        ),
    ] = False,
    include_transitive: Annotated[
        bool,
        typer.Option(
            '--include-transitive',
            help='With --include-declared and --maven-central: follow each declared dependency to the '
            'dependencies its own pom declares, the way a Maven build would, and include those too.',
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
    if include_test_scope and not include_declared:
        raise typer.BadParameter(
            '--include-test-scope widens what --include-declared reports; it does nothing on its own.',
            param_hint='--include-test-scope',
        )
    if include_transitive and not (include_declared and maven_central):
        raise typer.BadParameter(
            '--include-transitive follows declared dependencies through their poms on Maven Central; '
            'it needs both --include-declared and --maven-central.',
            param_hint='--include-transitive',
        )

    ctx.obj['binary_max_depth'] = max_depth
    ctx.obj['maven_central'] = maven_central
    ctx.obj['include_declared'] = include_declared
    ctx.obj['include_test_scope'] = include_test_scope
    ctx.obj['include_transitive'] = include_transitive

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
