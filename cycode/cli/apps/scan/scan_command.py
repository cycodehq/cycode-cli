from typing import Annotated, List, Optional

import click
import typer

from cycode.cli.cli_types import ScanTypeOption, ScaScanTypeOption, SeverityOption
from cycode.cli.config import config
from cycode.cli.consts import (
    ISSUE_DETECTED_STATUS_CODE,
    NO_ISSUES_STATUS_CODE,
    SCA_GRADLE_ALL_SUB_PROJECTS_FLAG,
    SCA_SKIP_RESTORE_DEPENDENCIES_FLAG,
)
from cycode.cli.utils import scan_utils
from cycode.cli.utils.get_api_client import get_scan_cycode_client
from cycode.cli.utils.sentry import add_breadcrumb


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
            rich_help_panel='Authentication options',
        ),
    ] = None,
    client_id: Annotated[
        Optional[str],
        typer.Option(
            help='Specify a Cycode client ID for this specific scan execution.',
            rich_help_panel='Authentication options',
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
        typer.Option('--sync', help='Run scan synchronously.', show_default='asynchronously'),
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
            rich_help_panel='SCA options',
        ),
    ] = (ScaScanTypeOption.PACKAGE_VULNERABILITIES, ScaScanTypeOption.LICENSE_COMPLIANCE),
    monitor: Annotated[
        bool,
        typer.Option(
            '--monitor',
            help='When specified, the scan results are recorded in the Discovery module.',
            rich_help_panel='SCA options',
        ),
    ] = False,
    no_restore: Annotated[
        bool,
        typer.Option(
            f'--{SCA_SKIP_RESTORE_DEPENDENCIES_FLAG}',
            help='When specified, Cycode will not run restore command. '
            'Will scan direct dependencies [bold]only[/bold]!',
            rich_help_panel='SCA options',
        ),
    ] = False,
    gradle_all_sub_projects: Annotated[
        bool,
        typer.Option(
            f'--{SCA_GRADLE_ALL_SUB_PROJECTS_FLAG}',
            help='When specified, Cycode will run gradle restore command for all sub projects. '
            'Should run from root project directory [bold]only[/bold]!',
            rich_help_panel='SCA options',
        ),
    ] = False,
) -> None:
    """:magnifying_glass_tilted_right: Scan the content for Secrets, IaC, SCA, and SAST violations.
    You'll need to specify which scan type to perform:
    [cyan]path[/cyan]/[cyan]repository[/cyan]/[cyan]commit_history[/cyan]."""
    add_breadcrumb('scan')

    if show_secret:
        ctx.obj['show_secret'] = show_secret
    else:
        ctx.obj['show_secret'] = config['result_printer']['default']['show_secret']

    if soft_fail:
        ctx.obj['soft_fail'] = soft_fail
    else:
        ctx.obj['soft_fail'] = config['soft_fail']

    ctx.obj['client'] = get_scan_cycode_client(client_id, client_secret, not ctx.obj['show_secret'])
    ctx.obj['scan_type'] = scan_type
    ctx.obj['sync'] = sync
    ctx.obj['severity_threshold'] = severity_threshold
    ctx.obj['monitor'] = monitor
    ctx.obj['report'] = report
    ctx.obj[SCA_SKIP_RESTORE_DEPENDENCIES_FLAG] = no_restore
    ctx.obj[SCA_GRADLE_ALL_SUB_PROJECTS_FLAG] = gradle_all_sub_projects

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
