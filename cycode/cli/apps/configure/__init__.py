import typer

from cycode.cli.apps.configure.configure_command import configure_command

app = typer.Typer()
app.command(name='configure', short_help='Initial command to configure your CLI client authentication.')(
    configure_command
)
