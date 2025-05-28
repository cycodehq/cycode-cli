import os
from typing import Annotated, Optional

import typer

from cycode.cli.apps.scan.commit_range_scanner import scan_pre_commit
from cycode.cli.utils.sentry import add_breadcrumb


def pre_commit_command(
    ctx: typer.Context,
    _: Annotated[Optional[list[str]], typer.Argument(help='Ignored arguments', hidden=True)] = None,
) -> None:
    add_breadcrumb('pre_commit')

    repo_path = os.getcwd()  # change locally for easy testing

    progress_bar = ctx.obj['progress_bar']
    progress_bar.start()

    scan_pre_commit(ctx, repo_path)
