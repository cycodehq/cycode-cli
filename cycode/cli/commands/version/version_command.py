import json

import click

from cycode import __version__
from cycode.cli.consts import PROGRAM_NAME


@click.command(short_help='Show the CLI version and exit.')
@click.pass_context
def version_command(context: click.Context) -> None:
    output = context.obj['output']

    prog = PROGRAM_NAME
    ver = __version__

    message = f'{prog}, version {ver}'
    if output == 'json':
        message = json.dumps({'name': prog, 'version': ver})

    click.echo(message, color=context.color)
    context.exit()
