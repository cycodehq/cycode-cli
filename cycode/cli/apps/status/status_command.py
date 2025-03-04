import typer

from cycode.cli.apps.status.get_cli_status import get_cli_status
from cycode.cli.cli_types import OutputTypeOption


def status_command(ctx: typer.Context) -> None:
    output = ctx.obj['output']

    cli_status = get_cli_status()
    message = cli_status.as_text()
    if output == OutputTypeOption.JSON:
        message = cli_status.as_json()

    typer.echo(message, color=ctx.color)
