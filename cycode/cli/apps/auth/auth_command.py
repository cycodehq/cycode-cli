import typer

from cycode.cli.apps.activation_manager import report_cli_activation, should_report_cli_activation
from cycode.cli.apps.auth.auth_manager import AuthManager
from cycode.cli.exceptions.handle_auth_errors import handle_auth_exception
from cycode.cli.logger import logger
from cycode.cli.models import CliResult
from cycode.cli.utils.get_api_client import get_scan_cycode_client


def auth_command(ctx: typer.Context) -> None:
    """:key: [bold cyan]Authenticate your machine with Cycode.[/]

    This command handles authentication with Cycode's security platform.

    Example usage:
    * `cycode auth`: Start interactive authentication
    * `cycode auth --help`: View authentication options
    """
    printer = ctx.obj.get('console_printer')

    try:
        logger.debug('Starting authentication process')

        auth_manager = AuthManager()
        auth_manager.authenticate()

        plugin_app_name = ctx.obj.get('plugin_app_name')
        plugin_app_version = ctx.obj.get('plugin_app_version')
        if should_report_cli_activation(plugin_app_name, plugin_app_version):
            scan_client = get_scan_cycode_client(ctx)
            report_cli_activation(scan_client.scan_cycode_client, plugin_app_name, plugin_app_version)

        result = CliResult(success=True, message='Successfully logged into cycode')
        printer.print_result(result)
    except Exception as err:
        handle_auth_exception(ctx, err)
