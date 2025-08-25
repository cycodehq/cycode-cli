from pathlib import Path
from typing import Annotated, Optional

import click
import typer

from cycode.cli.cli_types import ExportTypeOption, ScanTypeOption, ScaScanTypeOption, SeverityOption
from cycode.cli.consts import (
    ISSUE_DETECTED_STATUS_CODE,
    NO_ISSUES_STATUS_CODE,
)
from cycode.cli.files_collector.file_excluder import excluder
from cycode.cli.utils import scan_utils
from cycode.cli.utils.get_api_client import get_scan_cycode_client
from cycode.cli.utils.sentry import add_breadcrumb

_EXPORT_RICH_HELP_PANEL = 'Export options'
_SCA_RICH_HELP_PANEL = 'SCA options'
_SECRET_RICH_HELP_PANEL = 'Secret options'


def scan_command(
    ctx: typer.Context,
    scan_type: Annotated[
        ScanTypeOption,
        typer.Option(
            '--scan-type',
            '-t',
            help='Specify the type of scan you wish to execute.',
            case_sensitive=False,
        ),
    ] = ScanTypeOption.SECRET,
    soft_fail: Annotated[
        bool, typer.Option('--soft-fail', help='Run the scan without failing; always return a non-error status code.')
    ] = False,
    severity_threshold: Annotated[
        SeverityOption,
        typer.Option(
            help='Show violations only for the specified level or higher.',
            case_sensitive=False,
        ),
    ] = SeverityOption.INFO,
    sync: Annotated[
        bool,
        typer.Option(
            '--sync', help='Run scan synchronously (INTERNAL FOR IDEs).', show_default='asynchronously', hidden=True
        ),
    ] = False,
    report: Annotated[
        bool,
        typer.Option(
            '--cycode-report',
            help='When specified, displays a link to the scan report in the Cycode platform in the console output.',
        ),
    ] = False,
    show_secret: Annotated[
        bool, typer.Option('--show-secret', help='Show Secrets in plain text.', rich_help_panel=_SECRET_RICH_HELP_PANEL)
    ] = False,
    sca_scan: Annotated[
        list[ScaScanTypeOption],
        typer.Option(
            help='Specify the type of SCA scan you wish to execute.',
            rich_help_panel=_SCA_RICH_HELP_PANEL,
        ),
    ] = (ScaScanTypeOption.PACKAGE_VULNERABILITIES, ScaScanTypeOption.LICENSE_COMPLIANCE),
    monitor: Annotated[
        bool,
        typer.Option(
            '--monitor',
            help='When specified, the scan results are recorded in the Discovery module.',
            rich_help_panel=_SCA_RICH_HELP_PANEL,
        ),
    ] = False,
    no_restore: Annotated[
        bool,
        typer.Option(
            '--no-restore',
            help='When specified, Cycode will not run restore command. Will scan direct dependencies [b]only[/]!',
            rich_help_panel=_SCA_RICH_HELP_PANEL,
        ),
    ] = False,
    gradle_all_sub_projects: Annotated[
        bool,
        typer.Option(
            '--gradle-all-sub-projects',
            help='When specified, Cycode will run gradle restore command for all sub projects. '
            'Should run from root project directory [b]only[/]!',
            rich_help_panel=_SCA_RICH_HELP_PANEL,
        ),
    ] = False,
    maven_settings_file: Annotated[
        Optional[Path],
        typer.Option(
            '--maven-settings-file',
            show_default=False,
            help='When specified, Cycode will use this settings.xml file when building the maven dependency tree.',
            dir_okay=False,
            rich_help_panel=_SCA_RICH_HELP_PANEL,
        ),
    ] = None,
    export_type: Annotated[
        ExportTypeOption,
        typer.Option(
            '--export-type',
            case_sensitive=False,
            help='Specify the export type. '
            'HTML and SVG will export terminal output and rely on --output option. '
            'JSON always exports JSON.',
            rich_help_panel=_EXPORT_RICH_HELP_PANEL,
        ),
    ] = None,
    export_file: Annotated[
        Optional[Path],
        typer.Option(
            '--export-file',
            help='Export file. Path to the file where the export will be saved.',
            dir_okay=False,
            writable=True,
            rich_help_panel=_EXPORT_RICH_HELP_PANEL,
        ),
    ] = None,
) -> None:
    """:mag: [bold cyan]Scan code for vulnerabilities (Secrets, IaC, SCA, SAST).[/]

    This command scans your code for various types of security issues, including:
    * [yellow]Secrets:[/] Hardcoded credentials and sensitive information.
    * [dodger_blue1]Infrastructure as Code (IaC):[/] Misconfigurations in Terraform, CloudFormation, etc.
    * [green]Software Composition Analysis (SCA):[/] Vulnerabilities and license issues in dependencies.
    * [magenta]Static Application Security Testing (SAST):[/] Code quality and security flaws.

    Example usage:
    * `cycode scan path <PATH>`: Scan a specific local directory or file.
    * `cycode scan repository <PATH>`: Scan Git related files in a local Git repository.
    * `cycode scan commit-history <PATH>`: Scan the commit history of a local Git repository.

    """
    add_breadcrumb('scan')

    if export_file and export_type is None:
        raise typer.BadParameter(
            'Export type must be specified when --export-file is provided.',
            param_hint='--export-type',
        )
    if export_type and export_file is None:
        raise typer.BadParameter(
            'Export file must be specified when --export-type is provided.',
            param_hint='--export-file',
        )

    ctx.obj['show_secret'] = show_secret
    ctx.obj['soft_fail'] = soft_fail
    ctx.obj['scan_type'] = scan_type
    ctx.obj['sync'] = sync
    ctx.obj['severity_threshold'] = severity_threshold
    ctx.obj['monitor'] = monitor
    ctx.obj['maven_settings_file'] = maven_settings_file
    ctx.obj['report'] = report
    ctx.obj['gradle_all_sub_projects'] = gradle_all_sub_projects
    ctx.obj['no_restore'] = no_restore

    scan_client = get_scan_cycode_client(ctx)
    ctx.obj['client'] = scan_client

    remote_scan_config = scan_client.get_scan_configuration_safe(scan_type)
    if remote_scan_config:
        excluder.apply_scan_config(str(scan_type), remote_scan_config)

    if export_type and export_file:
        console_printer = ctx.obj['console_printer']
        console_printer.enable_recording(export_type, export_file)

    _sca_scan_to_context(ctx, sca_scan)


def _sca_scan_to_context(ctx: typer.Context, sca_scan_user_selected: list[str]) -> None:
    for sca_scan_option_selected in sca_scan_user_selected:
        ctx.obj[sca_scan_option_selected] = True


@click.pass_context
def scan_command_result_callback(ctx: click.Context, *_, **__) -> None:
    add_breadcrumb('scan_finalized')
    ctx.obj['scan_finalized'] = True

    progress_bar = ctx.obj.get('progress_bar')
    if progress_bar:
        progress_bar.stop()

    if ctx.obj['soft_fail']:
        raise typer.Exit(0)

    exit_code = NO_ISSUES_STATUS_CODE
    if scan_utils.is_scan_failed(ctx):
        exit_code = ISSUE_DETECTED_STATUS_CODE

    raise typer.Exit(exit_code)
