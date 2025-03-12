import typer

from cycode.cli.apps.auth.auth_manager import AuthManager
from cycode.cli.exceptions.handle_auth_errors import handle_auth_exception
from cycode.cli.logger import logger
from cycode.cli.models import CliResult
from cycode.cli.printers import ConsolePrinter
from cycode.cli.utils.sentry import add_breadcrumb


def auth_command(ctx: typer.Context) -> None:
    """Authenticates your machine."""
    add_breadcrumb('auth')

    if ctx.invoked_subcommand is not None:
        # if it is a subcommand, do nothing
        return

    try:
        logger.debug('Starting authentication process')

        auth_manager = AuthManager()
        auth_manager.authenticate()

        result = CliResult(success=True, message='Successfully logged into cycode')
        ConsolePrinter(ctx).print_result(result)
    except Exception as err:
        handle_auth_exception(ctx, err)
