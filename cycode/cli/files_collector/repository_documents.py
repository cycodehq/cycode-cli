import os
from collections.abc import Iterator
from typing import TYPE_CHECKING, Optional, Union

from cycode.cli import consts
from cycode.cli.files_collector.sca.sca_code_scanner import get_file_content_from_commit_diff
from cycode.cli.models import Document
from cycode.cli.utils.git_proxy import git_proxy
from cycode.cli.utils.path_utils import get_file_content, get_path_by_os

if TYPE_CHECKING:
    from git import Blob, Diff
    from git.objects.base import IndexObjUnion
    from git.objects.tree import TraversedTreeTup

    from cycode.cli.utils.progress_bar import BaseProgressBar, ProgressBarSection


def should_process_git_object(obj: 'Blob', _: int) -> bool:
    return obj.type == 'blob' and obj.size > 0


def get_git_repository_tree_file_entries(
    path: str, branch: str
) -> Union[Iterator['IndexObjUnion'], Iterator['TraversedTreeTup']]:
    return git_proxy.get_repo(path).tree(branch).traverse(predicate=should_process_git_object)


def parse_commit_range(commit_range: str, path: str) -> tuple[str, str]:
    from_commit_rev = None
    to_commit_rev = None

    for commit in git_proxy.get_repo(path).iter_commits(rev=commit_range):
        if not to_commit_rev:
            to_commit_rev = commit.hexsha
        from_commit_rev = commit.hexsha

    return from_commit_rev, to_commit_rev


def get_diff_file_path(file: 'Diff', relative: bool = False) -> Optional[str]:
    if relative:
        # relative to the repository root
        return file.b_path if file.b_path else file.a_path

    if file.b_blob:
        return file.b_blob.abspath
    return file.a_blob.abspath


def get_diff_file_content(file: 'Diff') -> str:
    return file.diff.decode('UTF-8', errors='replace')


def get_pre_commit_modified_documents(
    progress_bar: 'BaseProgressBar',
    progress_bar_section: 'ProgressBarSection',
    repo_path: str,
) -> tuple[list[Document], list[Document]]:
    git_head_documents = []
    pre_committed_documents = []

    repo = git_proxy.get_repo(repo_path)
    diff_index = repo.index.diff(consts.GIT_HEAD_COMMIT_REV, create_patch=True, R=True)
    progress_bar.set_section_length(progress_bar_section, len(diff_index))
    for diff in diff_index:
        progress_bar.update(progress_bar_section)

        file_path = get_path_by_os(get_diff_file_path(diff))
        file_content = get_file_content_from_commit_diff(repo, consts.GIT_HEAD_COMMIT_REV, diff)
        if file_content is not None:
            git_head_documents.append(Document(file_path, file_content))

        if os.path.exists(file_path):
            file_content = get_file_content(file_path)
            pre_committed_documents.append(Document(file_path, file_content))

    return git_head_documents, pre_committed_documents


def get_commit_range_modified_documents(
    progress_bar: 'BaseProgressBar',
    progress_bar_section: 'ProgressBarSection',
    path: str,
    from_commit_rev: str,
    to_commit_rev: str,
) -> tuple[list[Document], list[Document]]:
    from_commit_documents = []
    to_commit_documents = []

    repo = git_proxy.get_repo(path)
    diff = repo.commit(from_commit_rev).diff(to_commit_rev)

    modified_files_diff = [
        change for change in diff if change.change_type != consts.COMMIT_DIFF_DELETED_FILE_CHANGE_TYPE
    ]
    progress_bar.set_section_length(progress_bar_section, len(modified_files_diff))
    for blob in modified_files_diff:
        progress_bar.update(progress_bar_section)

        file_path = get_path_by_os(get_diff_file_path(blob))

        file_content = get_file_content_from_commit_diff(repo, from_commit_rev, blob)
        if file_content is not None:
            from_commit_documents.append(Document(file_path, file_content))

        file_content = get_file_content_from_commit_diff(repo, to_commit_rev, blob)
        if file_content is not None:
            to_commit_documents.append(Document(file_path, file_content))

    return from_commit_documents, to_commit_documents


def calculate_pre_receive_commit_range(branch_update_details: str) -> Optional[str]:
    end_commit = _get_end_commit_from_branch_update_details(branch_update_details)

    # branch is deleted, no need to perform scan
    if end_commit == consts.EMPTY_COMMIT_SHA:
        return None

    start_commit = _get_oldest_unupdated_commit_for_branch(end_commit)

    # no new commit to update found
    if not start_commit:
        return None

    return f'{start_commit}~1...{end_commit}'


def _get_end_commit_from_branch_update_details(update_details: str) -> str:
    # update details pattern: <start_commit> <end_commit> <ref>
    _, end_commit, _ = update_details.split()
    return end_commit


def _get_oldest_unupdated_commit_for_branch(commit: str) -> Optional[str]:
    # get a list of commits by chronological order that are not in the remote repository yet
    # more info about rev-list command: https://git-scm.com/docs/git-rev-list
    repo = git_proxy.get_repo(os.getcwd())
    not_updated_commits = repo.git.rev_list(commit, '--topo-order', '--reverse', '--not', '--all')

    commits = not_updated_commits.splitlines()
    if not commits:
        return None

    return commits[0]
