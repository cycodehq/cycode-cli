import typer

from cycode.cli.apps.auth.auth_command import auth_command
from cycode.cli.apps.auth.check_command import check_command

app = typer.Typer(
    name='auth',
    help='Authenticate your machine to associate the CLI with your Cycode account.',
    no_args_is_help=True,
)
app.callback(invoke_without_command=True)(auth_command)
app.command(name='check')(check_command)
