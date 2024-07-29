import click

from cycode.cli.commands.auth.auth_manager import AuthManager
from cycode.cli.exceptions.custom_exceptions import (
    KNOWN_USER_FRIENDLY_REQUEST_ERRORS,
    AuthProcessError,
    HttpUnauthorizedError,
    RequestHttpError,
)
from cycode.cli.models import CliError, CliErrors, CliResult
from cycode.cli.printers import ConsolePrinter
from cycode.cli.sentry import add_breadcrumb, capture_exception
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cli.utils.jwt_utils import get_user_and_tenant_ids_from_access_token
from cycode.cyclient import logger
from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient


@click.group(
    invoke_without_command=True, short_help='Authenticate your machine to associate the CLI with your Cycode account.'
)
@click.pass_context
def auth_command(context: click.Context) -> None:
    """Authenticates your machine."""
    add_breadcrumb('auth')

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


@auth_command.command(
    name='check', short_help='Checks that your machine is associating the CLI with your Cycode account.'
)
@click.pass_context
def authorization_check(context: click.Context) -> None:
    """Validates that your Cycode account has permission to work with the CLI."""
    add_breadcrumb('check')

    printer = ConsolePrinter(context)

    failed_auth_check_res = CliResult(success=False, message='Cycode authentication failed')

    client_id, client_secret = CredentialsManager().get_credentials()
    if not client_id or not client_secret:
        printer.print_result(failed_auth_check_res)
        return

    try:
        access_token = CycodeTokenBasedClient(client_id, client_secret).get_access_token()
        if not access_token:
            printer.print_result(failed_auth_check_res)
            return

        user_id, tenant_id = get_user_and_tenant_ids_from_access_token(access_token)
        printer.print_result(
            CliResult(
                success=True,
                message='Cycode authentication verified',
                data={'user_id': user_id, 'tenant_id': tenant_id},
            )
        )

        return
    except (RequestHttpError, HttpUnauthorizedError):
        ConsolePrinter(context).print_exception()

        printer.print_result(failed_auth_check_res)
        return


def _handle_exception(context: click.Context, e: Exception) -> None:
    ConsolePrinter(context).print_exception()

    errors: CliErrors = {
        **KNOWN_USER_FRIENDLY_REQUEST_ERRORS,
        AuthProcessError: CliError(
            code='auth_error', message='Authentication failed. Please try again later using the command `cycode auth`'
        ),
    }

    error = errors.get(type(e))
    if error:
        ConsolePrinter(context).print_error(error)
        return

    if isinstance(e, click.ClickException):
        raise e

    capture_exception(e)

    raise click.ClickException(str(e))
