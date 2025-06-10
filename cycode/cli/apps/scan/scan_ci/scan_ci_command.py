import os

import click
import typer

from cycode.cli.apps.scan.commit_range_scanner import scan_commit_range
from cycode.cli.apps.scan.scan_ci.ci_integrations import get_commit_range
from cycode.cli.utils.sentry import add_breadcrumb

# This command is not finished yet. It is not used in the codebase.


@click.command(
    short_help='Execute scan in a CI environment which relies on the '
    'CYCODE_TOKEN and CYCODE_REPO_LOCATION environment variables'
)
@click.pass_context
def scan_ci_command(ctx: typer.Context) -> None:
    add_breadcrumb('ci')
    scan_commit_range(ctx, repo_path=os.getcwd(), commit_range=get_commit_range())
