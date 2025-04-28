from typing import Annotated, List, Optional

import click
import typer

from cycode.cli.cli_types import ScanTypeOption, ScaScanTypeOption, SeverityOption
from cycode.cli.consts import (
    ISSUE_DETECTED_STATUS_CODE,
    NO_ISSUES_STATUS_CODE,
)
from cycode.cli.utils import scan_utils
from cycode.cli.utils.get_api_client import get_scan_cycode_client
from cycode.cli.utils.sentry import add_breadcrumb

_AUTH_RICH_HELP_PANEL = 'Authentication options'
_SCA_RICH_HELP_PANEL = 'SCA options'


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
    client_secret: Annotated[
        Optional[str],
        typer.Option(
            help='Specify a Cycode client secret for this specific scan execution.',
            rich_help_panel=_AUTH_RICH_HELP_PANEL,
        ),
    ] = None,
    client_id: Annotated[
        Optional[str],
        typer.Option(
            help='Specify a Cycode client ID for this specific scan execution.',
            rich_help_panel=_AUTH_RICH_HELP_PANEL,
        ),
    ] = None,
    show_secret: Annotated[bool, typer.Option('--show-secret', help='Show Secrets in plain text.')] = False,
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
            '--report',
            help='When specified, generates a violations report. '
            'A link to the report will be displayed in the console output.',
        ),
    ] = False,
    sca_scan: Annotated[
        List[ScaScanTypeOption],
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
            help='When specified, Cycode will not run restore command. ' 'Will scan direct dependencies [b]only[/]!',
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

    ctx.obj['show_secret'] = show_secret
    ctx.obj['soft_fail'] = soft_fail
    ctx.obj['client'] = get_scan_cycode_client(client_id, client_secret, not ctx.obj['show_secret'])
    ctx.obj['scan_type'] = scan_type
    ctx.obj['sync'] = sync
    ctx.obj['severity_threshold'] = severity_threshold
    ctx.obj['monitor'] = monitor
    ctx.obj['report'] = report

    _ = no_restore, gradle_all_sub_projects  # they are actually used; via ctx.params

    _sca_scan_to_context(ctx, sca_scan)


def _sca_scan_to_context(ctx: typer.Context, sca_scan_user_selected: List[str]) -> None:
    for sca_scan_option_selected in sca_scan_user_selected:
        ctx.obj[sca_scan_option_selected] = True


@click.pass_context
def scan_command_result_callback(ctx: click.Context, *_, **__) -> None:
    add_breadcrumb('scan_finalize')

    progress_bar = ctx.obj.get('progress_bar')
    if progress_bar:
        progress_bar.stop()

    if ctx.obj['soft_fail']:
        raise typer.Exit(0)

    exit_code = NO_ISSUES_STATUS_CODE
    if scan_utils.is_scan_failed(ctx):
        exit_code = ISSUE_DETECTED_STATUS_CODE

    raise typer.Exit(exit_code)
