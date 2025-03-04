import typer

from cycode.cli.apps.ignore.ignore_command import ignore_command

app = typer.Typer()
app.command(name='ignore', short_help='Ignores a specific value, path or rule ID.')(ignore_command)
