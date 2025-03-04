import typer

from cycode.cli.apps.auth.auth_common import get_authorization_info
from cycode.cli.models import CliResult
from cycode.cli.printers import ConsolePrinter
from cycode.cli.utils.sentry import add_breadcrumb


def check_command(ctx: typer.Context) -> None:
    """Checks that your machine is associating the CLI with your Cycode account."""
    add_breadcrumb('check')

    printer = ConsolePrinter(ctx)
    auth_info = get_authorization_info(ctx)
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
