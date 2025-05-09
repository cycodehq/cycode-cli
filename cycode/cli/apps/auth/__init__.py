import typer

from cycode.cli.apps.auth.auth_command import auth_command

_auth_command_docs = 'https://github.com/cycodehq/cycode-cli/blob/main/README.md#using-the-auth-command'
_auth_command_epilog = f'[bold]Documentation:[/] [link={_auth_command_docs}]{_auth_command_docs}[/link]'

app = typer.Typer(no_args_is_help=False)
app.command(name='auth', epilog=_auth_command_epilog, short_help='Authenticate your machine with Cycode.')(auth_command)
