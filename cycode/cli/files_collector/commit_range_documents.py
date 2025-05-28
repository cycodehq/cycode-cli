from typing import Optional

import typer

from cycode.cli.files_collector.repository_documents import get_diff_file_content, get_diff_file_path
from cycode.cli.models import Document
from cycode.cli.utils.git_proxy import git_proxy
from cycode.cli.utils.path_utils import get_path_by_os
from cycode.cli.utils.progress_bar import ScanProgressBarSection
from cycode.logger import get_logger

logger = get_logger('Commit Range Collector')


def _does_reach_to_max_commits_to_scan_limit(commit_ids: list[str], max_commits_count: Optional[int]) -> bool:
    if max_commits_count is None:
        return False

    return len(commit_ids) >= max_commits_count


def collect_commit_range_diff_documents(
    ctx: typer.Context, path: str, commit_range: str, max_commits_count: Optional[int] = None
) -> list[Document]:
    """Collects documents from a specified commit range in a Git repository.

    Return a list of Document objects containing the diffs of files changed in each commit.
    """
    progress_bar = ctx.obj['progress_bar']

    commit_ids_to_scan = []
    commit_documents_to_scan = []

    repo = git_proxy.get_repo(path)
    total_commits_count = int(repo.git.rev_list('--count', commit_range))
    logger.debug('Calculating diffs for %s commits in the commit range %s', total_commits_count, commit_range)

    progress_bar.set_section_length(ScanProgressBarSection.PREPARE_LOCAL_FILES, total_commits_count)

    for scanned_commits_count, commit in enumerate(repo.iter_commits(rev=commit_range)):
        if _does_reach_to_max_commits_to_scan_limit(commit_ids_to_scan, max_commits_count):
            logger.debug('Reached to max commits to scan count. Going to scan only %s last commits', max_commits_count)
            progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES, total_commits_count - scanned_commits_count)
            break

        progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES)

        commit_id = commit.hexsha
        commit_ids_to_scan.append(commit_id)
        parent = commit.parents[0] if commit.parents else git_proxy.get_null_tree()
        diff_index = commit.diff(parent, create_patch=True, R=True)
        for diff in diff_index:
            commit_documents_to_scan.append(
                Document(
                    path=get_path_by_os(get_diff_file_path(diff)),
                    content=get_diff_file_content(diff),
                    is_git_diff_format=True,
                    unique_id=commit_id,
                )
            )

        logger.debug(
            'Found all relevant files in commit %s',
            {'path': path, 'commit_range': commit_range, 'commit_id': commit_id},
        )

    logger.debug('List of commit ids to scan, %s', {'commit_ids': commit_ids_to_scan})

    return commit_documents_to_scan
