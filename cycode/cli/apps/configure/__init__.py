import typer

from cycode.cli.apps.configure.configure_command import configure_command

_configure_command_docs = 'https://github.com/cycodehq/cycode-cli/blob/main/README.md#using-the-configure-command'
_configure_command_epilog = f'[bold]Documentation:[/] [link={_configure_command_docs}]{_configure_command_docs}[/link]'


app = typer.Typer(no_args_is_help=True)
app.command(
    name='configure',
    epilog=_configure_command_epilog,
    short_help='Initial command to configure your CLI client authentication.',
)(configure_command)
