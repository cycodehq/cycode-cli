import typer

from cycode.cli.apps.status.status_command import status_command
from cycode.cli.apps.status.version_command import version_command

app = typer.Typer(no_args_is_help=True)
app.command(name='status', short_help='Show the CLI status and exit.')(status_command)
app.command(name='version', hidden=True, short_help='Alias to status command.')(version_command)
