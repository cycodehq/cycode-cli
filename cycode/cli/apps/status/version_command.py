import typer

from cycode.cli.apps.status.status_command import status_command
from cycode.cli.console import console


def version_command(ctx: typer.Context) -> None:
    console.print('[b yellow]This command is deprecated. Please use the "status" command instead.[/]')
    console.line()
    status_command(ctx)
