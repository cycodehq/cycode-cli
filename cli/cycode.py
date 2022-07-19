import logging
import click
import sys
from cli.config import config
from cli import code_scanner, __version__
from cyclient import ScanClient, K8SUpdaterClient, logger
from cli.user_settings.credentials_manager import CredentialsManager
from cli.user_settings.user_settings_commands import set_credentials, add_exclusions
from cli.user_settings.configuration_manager import ConfigurationManager

CONTEXT = dict()
ISSUE_DETECTED_STATUS_CODE = 1
NO_ISSUES_STATUS_CODE = 0


@click.group(
    commands={
        "repository": code_scanner.scan_repository,
        "commit_history": code_scanner.scan_repository_commit_history,
        "path": code_scanner.scan_path,
        "pre_commit": code_scanner.pre_commit_scan
    },
)
@click.option('--scan-type', '-t', default="secret",
              help="""
              \b
              Specify the scan you wish to execute (secret/iac), 
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
@click.option('--output', default='text',
              help="""
              \b
              Specify the results output (text/json), 
              the default is text
              """,
              type=click.Choice(['text', 'json']))
@click.pass_context
def code_scan(context: click.Context, scan_type, client_id, secret, show_secret, soft_fail, output):
    """ Scan content for secrets/IaC violations, You need to specify which scan type: ci/commit_history/path/repository/etc """
    if show_secret:
        context.obj["show_secret"] = show_secret
    else:
        context.obj["show_secret"] = config["result_printer"]["show_secret"]

    if soft_fail:
        context.obj["soft_fail"] = soft_fail
    else:
        context.obj["soft_fail"] = config["soft_fail"]

    context.obj["scan_type"] = scan_type
    context.obj["output"] = output
    context.obj["client"] = get_cycode_client(client_id, secret, "code_scan")

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
        "ignore": add_exclusions
    },
    context_settings=CONTEXT
)
@click.option(
    "--verbose", "-v", is_flag=True, default=False, help="Show detailed logs",
)
@click.version_option(__version__, prog_name="cycode")
@click.pass_context
def main_cli(context: click.Context, verbose: bool):
    context.ensure_object(dict)
    configuration_manager = ConfigurationManager()
    verbose = verbose or configuration_manager.get_verbose_flag()
    context.obj["verbose"] = verbose
    log_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(log_level)


def get_cycode_client(client_id, client_secret, execution_type):
    if not client_id or not client_secret:
        client_id, client_secret = _get_configured_credentials()
        if not client_id:
            raise click.ClickException("Cycode client id needed.")
        if not client_secret:
            raise click.ClickException("Cycode client secret is needed.")

    if execution_type == "code_scan":
        return ScanClient(client_secret=client_secret, client_id=client_id)

    return K8SUpdaterClient(client_secret=client_secret, client_id=client_id)


def _get_configured_credentials():
    credentials_manager = CredentialsManager()
    return credentials_manager.get_credentials()


def _should_fail_scan(context: click.Context):
    did_fail = context.obj.get("did_fail")
    issue_detected = context.obj.get("issue_detected")
    return did_fail or issue_detected


if __name__ == '__main__':
    main_cli()
