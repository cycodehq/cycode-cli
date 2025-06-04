from pathlib import Path
from typing import Annotated

import typer

from cycode.cli.apps.scan.commit_range_scanner import scan_commit_range
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.logger import logger
from cycode.cli.utils.sentry import add_breadcrumb


def commit_history_command(
    ctx: typer.Context,
    path: Annotated[
        Path, typer.Argument(exists=True, resolve_path=True, help='Path to Git repository to scan', show_default=False)
    ],
    commit_range: Annotated[
        str,
        typer.Option(
            '--commit-range',
            '-r',
            help='Scan a commit range in this Git repository (example: HEAD~1)',
            show_default='cycode scans all commit history',
        ),
    ] = '--all',
) -> None:
    try:
        add_breadcrumb('commit_history')

        logger.debug('Starting commit history scan process, %s', {'path': path, 'commit_range': commit_range})
        scan_commit_range(ctx, repo_path=str(path), commit_range=commit_range)
    except Exception as e:
        handle_scan_exception(ctx, e)
