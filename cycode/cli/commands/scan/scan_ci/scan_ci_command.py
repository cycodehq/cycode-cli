import os

import click

from cycode.cli.commands.scan.code_scanner import scan_commit_range
from cycode.cli.commands.scan.scan_ci.ci_integrations import get_commit_range

# This command is not finished yet. It is not used in the codebase.


@click.command(
    short_help='Execute scan in a CI environment which relies on the '
    'CYCODE_TOKEN and CYCODE_REPO_LOCATION environment variables'
)
@click.pass_context
def scan_ci_command(context: click.Context) -> None:
    scan_commit_range(context, path=os.getcwd(), commit_range=get_commit_range())
