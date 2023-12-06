import sys
from typing import List

import click

from cycode.cli.commands.scan.commit_history.commit_history_command import commit_history_command
from cycode.cli.commands.scan.path.path_command import path_command
from cycode.cli.commands.scan.pre_commit.pre_commit_command import pre_commit_command
from cycode.cli.commands.scan.pre_receive.pre_receive_command import pre_receive_command
from cycode.cli.commands.scan.repository.repository_command import repository_command
from cycode.cli.config import config
from cycode.cli.consts import (
    ISSUE_DETECTED_STATUS_CODE,
    NO_ISSUES_STATUS_CODE,
    SCA_SKIP_RESTORE_DEPENDENCIES_FLAG,
)
from cycode.cli.models import Severity
from cycode.cli.utils import scan_utils
from cycode.cli.utils.get_api_client import get_scan_cycode_client


@click.group(
    commands={
        'repository': repository_command,
        'commit_history': commit_history_command,
        'path': path_command,
        'pre_commit': pre_commit_command,
        'pre_receive': pre_receive_command,
    },
    short_help='Scan the content for Secrets/IaC/SCA/SAST violations. '
    'You`ll need to specify which scan type to perform: commit_history/path/repository/etc.',
)
@click.option(
    '--scan-type',
    '-t',
    default='secret',
    help='Specify the type of scan you wish to execute (the default is Secrets)',
    type=click.Choice(config['scans']['supported_scans']),
)
@click.option(
    '--secret',
    default=None,
    help='Specify a Cycode client secret for this specific scan execution.',
    type=str,
    required=False,
)
@click.option(
    '--client-id',
    default=None,
    help='Specify a Cycode client ID for this specific scan execution.',
    type=str,
    required=False,
)
@click.option(
    '--show-secret', is_flag=True, default=False, help='Show Secrets in plain text.', type=bool, required=False
)
@click.option(
    '--soft-fail',
    is_flag=True,
    default=False,
    help='Run the scan without failing; always return a non-error status code.',
    type=bool,
    required=False,
)
@click.option(
    '--severity-threshold',
    default=None,
    help='Show violations only for the specified level or higher (supported for SCA scan types only).',
    type=click.Choice([e.name for e in Severity]),
    required=False,
)
@click.option(
    '--sca-scan',
    default=None,
    help='Specify the type of SCA scan you wish to execute (the default is both).',
    multiple=True,
    type=click.Choice(config['scans']['supported_sca_scans']),
)
@click.option(
    '--monitor',
    is_flag=True,
    default=False,
    help='Used for SCA scan types only; when specified, the scan results are recorded in the Discovery module.',
    type=bool,
    required=False,
)
@click.option(
    '--report',
    is_flag=True,
    default=False,
    help='When specified, generates a violations report. A link to the report will be displayed in the console output.',
    type=bool,
    required=False,
)
@click.option(
    f'--{SCA_SKIP_RESTORE_DEPENDENCIES_FLAG}',
    is_flag=True,
    default=False,
    help='When specified, Cycode will not run restore command. Will scan direct dependencies ONLY!',
    type=bool,
    required=False,
)
@click.pass_context
def scan_command(
    context: click.Context,
    scan_type: str,
    secret: str,
    client_id: str,
    show_secret: bool,
    soft_fail: bool,
    severity_threshold: str,
    sca_scan: List[str],
    monitor: bool,
    report: bool,
    no_restore: bool,
) -> int:
    """Scans for Secrets, IaC, SCA or SAST violations."""
    if show_secret:
        context.obj['show_secret'] = show_secret
    else:
        context.obj['show_secret'] = config['result_printer']['default']['show_secret']

    if soft_fail:
        context.obj['soft_fail'] = soft_fail
    else:
        context.obj['soft_fail'] = config['soft_fail']

    context.obj['client'] = get_scan_cycode_client(client_id, secret, not context.obj['show_secret'])
    context.obj['scan_type'] = scan_type
    context.obj['severity_threshold'] = severity_threshold
    context.obj['monitor'] = monitor
    context.obj['report'] = report
    context.obj[SCA_SKIP_RESTORE_DEPENDENCIES_FLAG] = no_restore

    _sca_scan_to_context(context, sca_scan)

    return 1


def _sca_scan_to_context(context: click.Context, sca_scan_user_selected: List[str]) -> None:
    for sca_scan_option_selected in sca_scan_user_selected:
        context.obj[sca_scan_option_selected] = True


@scan_command.result_callback()
@click.pass_context
def finalize(context: click.Context, *_, **__) -> None:
    progress_bar = context.obj.get('progress_bar')
    if progress_bar:
        progress_bar.stop()

    if context.obj['soft_fail']:
        sys.exit(0)

    exit_code = NO_ISSUES_STATUS_CODE
    if scan_utils.is_scan_failed(context):
        exit_code = ISSUE_DETECTED_STATUS_CODE

    sys.exit(exit_code)
