import logging

import click
import sys

from typing import List

from cycode import __version__
from cycode.cli.models import Severity
from cycode.cli.config import config
from cycode.cli import code_scanner
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.user_settings.user_settings_commands import set_credentials, add_exclusions
from cycode.cli.auth.auth_command import authenticate
from cycode.cli.utils import scan_utils
from cycode.cyclient import logger
from cycode.cyclient.scan_config.scan_config_creator import create_scan_client

CONTEXT = dict()
ISSUE_DETECTED_STATUS_CODE = 1
NO_ISSUES_STATUS_CODE = 0


@click.group(
    commands={
        "repository": code_scanner.scan_repository,
        "commit_history": code_scanner.scan_repository_commit_history,
        "path": code_scanner.scan_path,
        "pre_commit": code_scanner.pre_commit_scan,
        "pre_receive": code_scanner.pre_receive_scan
    },
)
@click.option('--scan-type', '-t', default="secret",
              help="""
              \b
              Specify the scan you wish to execute (secret/iac/sca), 
              the default is secret
              """,
              type=click.Choice(config['scans']['supported_scans']))
@click.option('--secret',
              default=None,
              help='Specify a Cycode client secret for this specific scan execution',
              type=str,
              required=False)
@click.option('--client-id',
              default=None,
              help='Specify a Cycode client ID for this specific scan execution',
              type=str,
              required=False)
@click.option('--show-secret',
              is_flag=True,
              default=False,
              help='Show secrets in plain text',
              type=bool,
              required=False)
@click.option('--soft-fail',
              is_flag=True,
              default=False,
              help='Run scan without failing, always return a non-error status code',
              type=bool,
              required=False)
@click.option('--output', default=None,
              help="""
              \b
              Specify the results output (text/json), 
              the default is text
              """,
              type=click.Choice(['text', 'json']))
@click.option('--severity-threshold',
              default=None,
              help='Show only violations at the specified level or higher (supported for SCA scan type only).',
              type=click.Choice([e.name for e in Severity]),
              required=False)
@click.option('--sca-scan',
              default=None,
              help="Specify the sca scan you wish to execute (package-vulnerabilities/license-compliance), the default is both",
              multiple=True,
              type=click.Choice(config['scans']['supported_sca_scans']))
@click.option('--monitor',
              is_flag=True,
              default=False,
              help="When specified, the scan results will be recorded in the knowledge graph. Please note that when working in 'monitor' mode, the knowledge graph will not be updated as a result of SCM events (Push, Repo creation).(supported for SCA scan type only).",
              type=bool,
              required=False)
@click.option('--report',
              is_flag=True,
              default=False,
              help="When specified, a violations report will be generated. A URL link to the report will be printed as an output to the command execution",
              type=bool,
              required=False)
@click.pass_context
def code_scan(context: click.Context, scan_type, client_id, secret, show_secret, soft_fail, output, severity_threshold,
              sca_scan: List[str], monitor, report):
    """ Scan content for secrets/IaC/sca/SAST violations, You need to specify which scan type: ci/commit_history/path/repository/etc """
    if show_secret:
        context.obj["show_secret"] = show_secret
    else:
        context.obj["show_secret"] = config["result_printer"]["default"]["show_secret"]

    if soft_fail:
        context.obj["soft_fail"] = soft_fail
    else:
        context.obj["soft_fail"] = config["soft_fail"]

    context.obj["scan_type"] = scan_type
    if output is not None:
        # save backward compatability with old style command
        context.obj["output"] = output
    context.obj["client"] = get_cycode_client(client_id, secret)
    context.obj["severity_threshold"] = severity_threshold
    context.obj["monitor"] = monitor
    context.obj["report"] = report
    _sca_scan_to_context(context, sca_scan)

    return 1


@code_scan.result_callback()
@click.pass_context
def finalize(context: click.Context, *args, **kwargs):
    if context.obj["soft_fail"]:
        sys.exit(0)

    sys.exit(ISSUE_DETECTED_STATUS_CODE if _should_fail_scan(context) else NO_ISSUES_STATUS_CODE)


@click.group(
    commands={
        "scan": code_scan,
        "configure": set_credentials,
        "ignore": add_exclusions,
        "auth": authenticate
    },
    context_settings=CONTEXT
)
@click.option(
    "--verbose", "-v", is_flag=True, default=False, help="Show detailed logs",
)
@click.option(
    '--output',
    default='text',
    help='Specify the output (text/json), the default is text',
    type=click.Choice(['text', 'json'])
)
@click.version_option(__version__, prog_name="cycode")
@click.pass_context
def main_cli(context: click.Context, verbose: bool, output: str):
    context.ensure_object(dict)
    configuration_manager = ConfigurationManager()

    verbose = verbose or configuration_manager.get_verbose_flag()
    context.obj['verbose'] = verbose
    log_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(log_level)

    context.obj['output'] = output


def get_cycode_client(client_id, client_secret):
    if not client_id or not client_secret:
        client_id, client_secret = _get_configured_credentials()
        if not client_id:
            raise click.ClickException("Cycode client id needed.")
        if not client_secret:
            raise click.ClickException("Cycode client secret is needed.")

    return create_scan_client(client_id, client_secret)


def _get_configured_credentials():
    credentials_manager = CredentialsManager()
    return credentials_manager.get_credentials()


def _should_fail_scan(context: click.Context):
    return scan_utils.is_scan_failed(context)


def _sca_scan_to_context(context: click.Context, sca_scan_user_selected: List[str]):
    for sca_scan_option_selected in sca_scan_user_selected:
        context.obj[sca_scan_option_selected] = True


if __name__ == '__main__':
    main_cli()
