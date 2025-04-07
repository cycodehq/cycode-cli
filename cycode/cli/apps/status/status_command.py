import typer

from cycode.cli.apps.status.get_cli_status import get_cli_status
from cycode.cli.cli_types import OutputTypeOption
from cycode.cli.console import console


def status_command(ctx: typer.Context) -> None:
    output = ctx.obj['output']

    highlight = True
    cli_status = get_cli_status()
    message = cli_status.as_text()

    if output == OutputTypeOption.JSON:
        highlight = False
        message = cli_status.as_json()

    console.print(message, highlight=highlight)
