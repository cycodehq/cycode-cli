from pathlib import Path
from typing import Annotated

import typer

from cycode.cli.apps.scan.code_scanner import scan_disk_files
from cycode.cli.logger import logger
from cycode.cli.utils.sentry import add_breadcrumb


def path_command(
    ctx: typer.Context,
    paths: Annotated[
        list[Path], typer.Argument(exists=True, resolve_path=True, help='Paths to scan', show_default=False)
    ],
) -> None:
    add_breadcrumb('path')

    progress_bar = ctx.obj['progress_bar']
    progress_bar.start()

    logger.debug('Starting path scan process, %s', {'paths': paths})

    tuple_paths = tuple(str(path) for path in paths)
    scan_disk_files(ctx, tuple_paths)
