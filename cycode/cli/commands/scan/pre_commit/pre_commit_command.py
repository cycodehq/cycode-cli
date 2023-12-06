import os
from typing import List

import click
from git import Repo

from cycode.cli import consts
from cycode.cli.commands.scan.code_scanner import scan_documents, scan_sca_pre_commit
from cycode.cli.files_collector.excluder import exclude_irrelevant_documents_to_scan
from cycode.cli.files_collector.repository_documents import (
    get_diff_file_content,
    get_diff_file_path,
)
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import (
    get_path_by_os,
)
from cycode.cli.utils.progress_bar import ScanProgressBarSection


@click.command(short_help='Use this command to scan any content that was not committed yet.')
@click.argument('ignored_args', nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def pre_commit_command(context: click.Context, ignored_args: List[str]) -> None:
    scan_type = context.obj['scan_type']

    progress_bar = context.obj['progress_bar']
    progress_bar.start()

    if scan_type == consts.SCA_SCAN_TYPE:
        scan_sca_pre_commit(context)
        return

    diff_files = Repo(os.getcwd()).index.diff('HEAD', create_patch=True, R=True)

    progress_bar.set_section_length(ScanProgressBarSection.PREPARE_LOCAL_FILES, len(diff_files))

    documents_to_scan = []
    for file in diff_files:
        progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES)
        documents_to_scan.append(Document(get_path_by_os(get_diff_file_path(file)), get_diff_file_content(file)))

    documents_to_scan = exclude_irrelevant_documents_to_scan(scan_type, documents_to_scan)
    scan_documents(context, documents_to_scan, is_git_diff=True)
