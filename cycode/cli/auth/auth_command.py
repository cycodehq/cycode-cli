import click
import traceback

from cycode.cli.models import CliResult, CliErrors, CliError
from cycode.cli.printers import ConsolePrinter
from cycode.cli.auth.auth_manager import AuthManager
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cli.exceptions.custom_exceptions import AuthProcessError, NetworkError, HttpUnauthorizedError
from cycode.cyclient import logger
from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient


@click.group(invoke_without_command=True)
@click.pass_context
def authenticate(context: click.Context):
    """ Authenticates your machine to associate CLI with your cycode account """
    if context.invoked_subcommand is not None:
        # if it is a subcommand do nothing
        return

    try:
        logger.debug('Starting authentication process')

        auth_manager = AuthManager()
        auth_manager.authenticate()

        result = CliResult(success=True, message='Successfully logged into cycode')
        ConsolePrinter(context).print_result(result)
    except Exception as e:
        _handle_exception(context, e)


@authenticate.command(name='check')
@click.pass_context
def authorization_check(context: click.Context):
    """ Check your machine associating CLI with your cycode account """
    printer = ConsolePrinter(context)

    passed_auth_check_res = CliResult(success=True, message='You are authorized')
    failed_auth_check_res = CliResult(success=False, message='You are not authorized')

    client_id, client_secret = CredentialsManager().get_credentials()
    if not client_id or not client_secret:
        return printer.print_result(failed_auth_check_res)

    try:
        if CycodeTokenBasedClient(client_id, client_secret).api_token:
            return printer.print_result(passed_auth_check_res)
    except (NetworkError, HttpUnauthorizedError):
        if context.obj['verbose']:
            click.secho(f'Error: {traceback.format_exc()}', fg='red', nl=False)

        return printer.print_result(failed_auth_check_res)


def _handle_exception(context: click.Context, e: Exception):
    if context.obj['verbose']:
        click.secho(f'Error: {traceback.format_exc()}', fg='red', nl=False)

    errors: CliErrors = {
        AuthProcessError: CliError(
            code='auth_error',
            message='Authentication failed. Please try again later using the command `cycode auth`'
        ),
        NetworkError: CliError(
            code='cycode_error',
            message='Authentication failed. Please try again later using the command `cycode auth`'
        ),
    }

    error = errors.get(type(e))
    if error:
        return ConsolePrinter(context).print_error(error)

    if isinstance(e, click.ClickException):
        raise e

    raise click.ClickException(str(e))
