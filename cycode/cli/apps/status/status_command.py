import typer

from cycode.cli.apps.status.get_cli_status import get_cli_status
from cycode.cli.cli_types import OutputTypeOption
from cycode.cli.console import console


def status_command(ctx: typer.Context) -> None:
    output = ctx.obj['output']

    cli_status = get_cli_status()
    if output == OutputTypeOption.JSON:
        console.print_json(cli_status.as_json())
    else:
        console.print(cli_status.as_text())
