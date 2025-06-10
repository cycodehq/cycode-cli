from pathlib import Path
from typing import Annotated, Optional

import click
import typer

from cycode.cli import consts
from cycode.cli.apps.scan.code_scanner import scan_documents
from cycode.cli.apps.scan.scan_parameters import get_scan_parameters
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.files_collector.file_excluder import excluder
from cycode.cli.files_collector.repository_documents import get_git_repository_tree_file_entries
from cycode.cli.files_collector.sca.sca_file_collector import add_sca_dependencies_tree_documents_if_needed
from cycode.cli.logger import logger
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_path_by_os
from cycode.cli.utils.progress_bar import ScanProgressBarSection
from cycode.cli.utils.sentry import add_breadcrumb


def repository_command(
    ctx: typer.Context,
    path: Annotated[
        Path, typer.Argument(exists=True, resolve_path=True, help='Path to Git repository to scan.', show_default=False)
    ],
    branch: Annotated[
        Optional[str], typer.Option('--branch', '-b', help='Branch to scan.', show_default='default branch')
    ] = None,
) -> None:
    try:
        add_breadcrumb('repository')

        logger.debug('Starting repository scan process, %s', {'path': path, 'branch': branch})

        scan_type = ctx.obj['scan_type']
        monitor = ctx.obj.get('monitor')
        if monitor and scan_type != consts.SCA_SCAN_TYPE:
            raise click.ClickException('Monitor flag is currently supported for SCA scan type only')

        progress_bar = ctx.obj['progress_bar']
        progress_bar.start()

        file_entries = list(get_git_repository_tree_file_entries(str(path), branch))
        progress_bar.set_section_length(ScanProgressBarSection.PREPARE_LOCAL_FILES, len(file_entries))

        documents_to_scan = []
        for blob in file_entries:
            # FIXME(MarshalX): probably file could be tree or submodule too. we expect blob only
            progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES)

            absolute_path = get_path_by_os(blob.abspath)
            file_path = get_path_by_os(blob.path) if monitor else absolute_path
            documents_to_scan.append(
                Document(
                    file_path,
                    blob.data_stream.read().decode('UTF-8', errors='replace'),
                    absolute_path=absolute_path,
                )
            )

        documents_to_scan = excluder.exclude_irrelevant_documents_to_scan(scan_type, documents_to_scan)

        add_sca_dependencies_tree_documents_if_needed(ctx, scan_type, documents_to_scan)

        logger.debug('Found all relevant files for scanning %s', {'path': path, 'branch': branch})
        scan_documents(ctx, documents_to_scan, get_scan_parameters(ctx, (str(path),)))
    except Exception as e:
        handle_scan_exception(ctx, e)
