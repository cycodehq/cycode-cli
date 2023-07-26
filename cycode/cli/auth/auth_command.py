import traceback

import click

from cycode.cli.auth.auth_manager import AuthManager
from cycode.cli.exceptions.custom_exceptions import AuthProcessError, HttpUnauthorizedError, NetworkError
from cycode.cli.models import CliError, CliErrors, CliResult
from cycode.cli.printers import ConsolePrinter
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cyclient import logger
from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient


@click.group(
    invoke_without_command=True, short_help='Authenticate your machine to associate the CLI with your Cycode account.'
)
@click.pass_context
def authenticate(context: click.Context) -> None:
    """Authenticates your machine."""
    if context.invoked_subcommand is not None:
        # if it is a subcommand, do nothing
        return

    try:
        logger.debug('Starting authentication process')

        auth_manager = AuthManager()
        auth_manager.authenticate()

        result = CliResult(success=True, message='Successfully logged into cycode')
        ConsolePrinter(context).print_result(result)
    except Exception as e:
        _handle_exception(context, e)


@authenticate.command(
    name='check', short_help='Checks that your machine is associating the CLI with your Cycode account.'
)
@click.pass_context
def authorization_check(context: click.Context) -> None:
    """Validates that your Cycode account has permission to work with the CLI."""
    printer = ConsolePrinter(context)

    passed_auth_check_res = CliResult(success=True, message='Cycode authentication verified')
    failed_auth_check_res = CliResult(success=False, message='Cycode authentication failed')

    client_id, client_secret = CredentialsManager().get_credentials()
    if not client_id or not client_secret:
        printer.print_result(failed_auth_check_res)
        return

    try:
        if CycodeTokenBasedClient(client_id, client_secret).api_token:
            printer.print_result(passed_auth_check_res)
            return
    except (NetworkError, HttpUnauthorizedError):
        if context.obj['verbose']:
            click.secho(f'Error: {traceback.format_exc()}', fg='red')

        printer.print_result(failed_auth_check_res)
        return


def _handle_exception(context: click.Context, e: Exception) -> None:
    if context.obj['verbose']:
        click.secho(f'Error: {traceback.format_exc()}', fg='red')

    errors: CliErrors = {
        AuthProcessError: CliError(
            code='auth_error', message='Authentication failed. Please try again later using the command `cycode auth`'
        ),
        NetworkError: CliError(
            code='cycode_error', message='Authentication failed. Please try again later using the command `cycode auth`'
        ),
    }

    error = errors.get(type(e))
    if error:
        ConsolePrinter(context).print_error(error)
        return

    if isinstance(e, click.ClickException):
        raise e

    raise click.ClickException(str(e))
