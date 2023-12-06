from typing import Tuple

import click

from cycode.cli.commands.scan.code_scanner import scan_disk_files
from cycode.cyclient import logger


@click.command(short_help='Scan the files in the path provided in the command.')
@click.argument('paths', nargs=-1, type=click.Path(exists=True, resolve_path=True), required=True)
@click.pass_context
def path_command(context: click.Context, paths: Tuple[str]) -> None:
    progress_bar = context.obj['progress_bar']
    progress_bar.start()

    logger.debug('Starting path scan process, %s', {'paths': paths})
    scan_disk_files(context, paths)
