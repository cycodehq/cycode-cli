import click

from cycode.cli.commands.scan.code_scanner import scan_commit_range
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cyclient import logger


@click.command(short_help='Scan all the commits history in this git repository.')
@click.argument('path', nargs=1, type=click.Path(exists=True, resolve_path=True), required=True)
@click.option(
    '--commit_range',
    '-r',
    help='Scan a commit range in this git repository, by default cycode scans all commit history (example: HEAD~1)',
    type=click.STRING,
    default='--all',
    required=False,
)
@click.pass_context
def commit_history_command(context: click.Context, path: str, commit_range: str) -> None:
    try:
        logger.debug('Starting commit history scan process, %s', {'path': path, 'commit_range': commit_range})
        scan_commit_range(context, path=path, commit_range=commit_range)
    except Exception as e:
        handle_scan_exception(context, e)
