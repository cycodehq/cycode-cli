import click

from cycode.cli.commands.auth.auth_manager import AuthManager
from cycode.cli.commands.auth_common import get_authorization_info
from cycode.cli.exceptions.custom_exceptions import (
    KNOWN_USER_FRIENDLY_REQUEST_ERRORS,
    AuthProcessError,
)
from cycode.cli.models import CliError, CliErrors, CliResult
from cycode.cli.printers import ConsolePrinter
from cycode.cli.sentry import add_breadcrumb, capture_exception
from cycode.cyclient import logger


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
    auth_info = get_authorization_info(context)
    if auth_info is None:
        printer.print_result(CliResult(success=False, message='Cycode authentication failed'))
        return

    printer.print_result(
        CliResult(
            success=True,
            message='Cycode authentication verified',
            data={'user_id': auth_info.user_id, 'tenant_id': auth_info.tenant_id},
        )
    )


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
