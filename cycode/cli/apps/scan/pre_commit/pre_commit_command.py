import os
from typing import Annotated, Optional

import typer

from cycode.cli import consts
from cycode.cli.apps.scan.code_scanner import get_scan_parameters, scan_documents, scan_sca_pre_commit
from cycode.cli.files_collector.excluder import excluder
from cycode.cli.files_collector.repository_documents import (
    get_diff_file_content,
    get_diff_file_path,
)
from cycode.cli.models import Document
from cycode.cli.utils.git_proxy import git_proxy
from cycode.cli.utils.path_utils import (
    get_path_by_os,
)
from cycode.cli.utils.progress_bar import ScanProgressBarSection
from cycode.cli.utils.sentry import add_breadcrumb


def pre_commit_command(
    ctx: typer.Context,
    _: Annotated[Optional[list[str]], typer.Argument(help='Ignored arguments', hidden=True)] = None,
) -> None:
    add_breadcrumb('pre_commit')

    scan_type = ctx.obj['scan_type']

    repo_path = os.getcwd()  # change locally for easy testing

    progress_bar = ctx.obj['progress_bar']
    progress_bar.start()

    if scan_type == consts.SCA_SCAN_TYPE:
        scan_sca_pre_commit(ctx, repo_path)
        return

    diff_files = git_proxy.get_repo(repo_path).index.diff(consts.GIT_HEAD_COMMIT_REV, create_patch=True, R=True)

    progress_bar.set_section_length(ScanProgressBarSection.PREPARE_LOCAL_FILES, len(diff_files))

    documents_to_scan = []
    for file in diff_files:
        progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES)
        documents_to_scan.append(Document(get_path_by_os(get_diff_file_path(file)), get_diff_file_content(file)))

    documents_to_scan = excluder.exclude_irrelevant_documents_to_scan(scan_type, documents_to_scan)
    scan_documents(ctx, documents_to_scan, get_scan_parameters(ctx), is_git_diff=True)
