import typer

from cycode.cli.apps.auth.auth_manager import AuthManager
from cycode.cli.exceptions.handle_auth_errors import handle_auth_exception
from cycode.cli.logger import logger
from cycode.cli.models import CliResult
from cycode.cli.utils.sentry import add_breadcrumb


def auth_command(ctx: typer.Context) -> None:
    """:key: [bold cyan]Authenticate your machine with Cycode.[/]

    This command handles authentication with Cycode's security platform.

    Example usage:
    * `cycode auth`: Start interactive authentication
    * `cycode auth --help`: View authentication options
    """
    add_breadcrumb('auth')
    printer = ctx.obj.get('console_printer')

    try:
        logger.debug('Starting authentication process')

        auth_manager = AuthManager()
        auth_manager.authenticate()

        result = CliResult(success=True, message='Successfully logged into cycode')
        printer.print_result(result)
    except Exception as err:
        handle_auth_exception(ctx, err)
