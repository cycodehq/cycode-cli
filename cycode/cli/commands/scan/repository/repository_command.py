import os

import click

from cycode.cli import consts
from cycode.cli.commands.scan.code_scanner import get_scan_parameters, scan_documents
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.files_collector.excluder import exclude_irrelevant_documents_to_scan
from cycode.cli.files_collector.repository_documents import get_git_repository_tree_file_entries
from cycode.cli.files_collector.sca.sca_code_scanner import perform_pre_scan_documents_actions
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_path_by_os
from cycode.cli.utils.progress_bar import ScanProgressBarSection
from cycode.cyclient import logger


@click.command(short_help='Scan the git repository including its history.')
@click.argument('path', nargs=1, type=click.Path(exists=True, resolve_path=True), required=True)
@click.option(
    '--branch',
    '-b',
    default=None,
    help='Branch to scan, if not set scanning the default branch',
    type=str,
    required=False,
)
@click.pass_context
def repository_command(context: click.Context, path: str, branch: str) -> None:
    try:
        logger.debug('Starting repository scan process, %s', {'path': path, 'branch': branch})

        scan_type = context.obj['scan_type']
        monitor = context.obj.get('monitor')
        if monitor and scan_type != consts.SCA_SCAN_TYPE:
            raise click.ClickException('Monitor flag is currently supported for SCA scan type only')

        progress_bar = context.obj['progress_bar']
        progress_bar.start()

        file_entries = list(get_git_repository_tree_file_entries(path, branch))
        progress_bar.set_section_length(ScanProgressBarSection.PREPARE_LOCAL_FILES, len(file_entries))

        documents_to_scan = []
        for file in file_entries:
            # FIXME(MarshalX): probably file could be tree or submodule too. we expect blob only
            progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES)

            file_path = file.path if monitor else get_path_by_os(os.path.join(path, file.path))
            documents_to_scan.append(Document(file_path, file.data_stream.read().decode('UTF-8', errors='replace')))

        documents_to_scan = exclude_irrelevant_documents_to_scan(scan_type, documents_to_scan)

        perform_pre_scan_documents_actions(context, scan_type, documents_to_scan, is_git_diff=False)

        logger.debug('Found all relevant files for scanning %s', {'path': path, 'branch': branch})
        scan_documents(
            context, documents_to_scan, is_git_diff=False, scan_parameters=get_scan_parameters(context, (path,))
        )
    except Exception as e:
        handle_scan_exception(context, e)
