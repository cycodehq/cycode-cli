import os
import sys
from typing import TYPE_CHECKING, Optional

import typer

from cycode.cli import consts
from cycode.cli.files_collector.repository_documents import (
    get_file_content_from_commit_path,
)
from cycode.cli.models import Document
from cycode.cli.utils.git_proxy import git_proxy
from cycode.cli.utils.path_utils import get_file_content, get_path_by_os
from cycode.cli.utils.progress_bar import ScanProgressBarSection
from cycode.logger import get_logger

if TYPE_CHECKING:
    from git import Blob, Diff, DiffIndex, Repo

    from cycode.cli.utils.progress_bar import BaseProgressBar, ProgressBarSection

logger = get_logger('Commit Range Collector')


def get_safe_head_reference_for_diff(repo: 'Repo') -> str:
    """Get a safe reference to use for diffing against the current HEAD.
    In repositories with no commits, HEAD doesn't exist, so we return the empty tree hash.

    Args:
        repo: Git repository object

    Returns:
        Either "HEAD" string if commits exist, or empty tree hash if no commits exist
    """
    try:
        repo.rev_parse(consts.GIT_HEAD_COMMIT_REV)
        return consts.GIT_HEAD_COMMIT_REV
    except Exception as e:  # actually gitdb.exc.BadObject; no import because of lazy loading
        logger.debug(
            'Repository has no commits, using empty tree hash for diffs, %s',
            {'repo_path': repo.working_tree_dir},
            exc_info=e,
        )

        # Repository has no commits, use the universal empty tree hash
        # This is the standard Git approach for initial commits
        return consts.GIT_EMPTY_TREE_OBJECT


def get_staged_diff_index(repo: 'Repo', paths: Optional[list[str]] = None) -> tuple[str, 'DiffIndex']:
    """Diff the index against HEAD, or against the empty tree in repositories with no commits.

    GitPython only inverts the `R` flag for HEAD, so `R` must be off for the empty tree to keep
    staged content showing up as added lines in both cases.

    Args:
        repo: Git repository object
        paths: Optional pathspec to scope the diff to

    Returns:
        The reference that was diffed against, and the resulting diff index
    """
    head_reference = get_safe_head_reference_for_diff(repo)
    reverse = head_reference == consts.GIT_HEAD_COMMIT_REV
    return head_reference, repo.index.diff(head_reference, create_patch=True, R=reverse, paths=paths or None)


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

    if commit_range == consts.COMMIT_RANGE_ALL_COMMITS:
        # everything reachable from HEAD, including the root commit
        normalized_commit_range = consts.GIT_HEAD_COMMIT_REV
    else:
        normalized_commit_range = normalize_commit_range(commit_range, path)

    total_commits_count = int(repo.git.rev_list('--count', normalized_commit_range))
    logger.debug(
        'Calculating diffs for %s commits in the commit range %s', total_commits_count, normalized_commit_range
    )

    progress_bar.set_section_length(ScanProgressBarSection.PREPARE_LOCAL_FILES, total_commits_count)

    for scanned_commits_count, commit in enumerate(repo.iter_commits(rev=normalized_commit_range)):
        if _does_reach_to_max_commits_to_scan_limit(commit_ids_to_scan, max_commits_count):
            logger.debug('Reached to max commits to scan count. Going to scan only %s last commits', max_commits_count)
            progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES, total_commits_count - scanned_commits_count)
            break

        progress_bar.update(ScanProgressBarSection.PREPARE_LOCAL_FILES)

        commit_id = commit.hexsha
        commit_ids_to_scan.append(commit_id)
        if commit.parents:
            diff_index = commit.diff(commit.parents[0], create_patch=True, R=True)
        else:
            diff_index = commit.diff(git_proxy.get_null_tree(), create_patch=True)
        for diff in diff_index:
            commit_documents_to_scan.append(
                Document(
                    path=get_path_by_os(get_diff_file_path(diff, repo=repo)),
                    content=get_diff_file_content(diff),
                    is_git_diff_format=True,
                    unique_id=commit_id,
                )
            )

        logger.debug(
            'Found all relevant files in commit %s',
            {
                'path': path,
                'commit_range': commit_range,
                'normalized_commit_range': normalized_commit_range,
                'commit_id': commit_id,
            },
        )

    logger.debug('List of commit ids to scan, %s', {'commit_ids': commit_ids_to_scan})

    return commit_documents_to_scan


def calculate_pre_receive_commit_range(repo_path: str, branch_update_details: str) -> Optional[str]:
    end_commit = _get_end_commit_from_branch_update_details(branch_update_details)

    # branch is deleted, no need to perform scan
    if end_commit == consts.EMPTY_COMMIT_SHA:
        return None

    repo = git_proxy.get_repo(repo_path)
    start_commit = _get_oldest_unupdated_commit_for_branch(repo, end_commit)

    # no new commit to update found
    if not start_commit:
        return None

    # If the oldest not-yet-updated commit has no parent (root commit or orphaned history),
    # using '~1' will fail. In that case, scan from the end commit, which effectively
    # includes the entire history reachable from it (which is exactly what we need here).

    if not bool(repo.commit(start_commit).parents):
        return f'{end_commit}'

    return f'{start_commit}~1...{end_commit}'


def _get_end_commit_from_branch_update_details(update_details: str) -> str:
    # update details pattern: <start_commit> <end_commit> <ref>
    _, end_commit, _ = update_details.split()
    return end_commit


def _get_oldest_unupdated_commit_for_branch(repo: 'Repo', commit: str) -> Optional[str]:
    # get a list of commits by chronological order that are not in the remote repository yet
    # more info about rev-list command: https://git-scm.com/docs/git-rev-list

    not_updated_commits = repo.git.rev_list(commit, '--topo-order', '--reverse', '--not', '--all')

    commits = not_updated_commits.splitlines()
    if not commits:
        return None

    return commits[0]


def _get_file_content_from_commit_diff(repo: 'Repo', commit: str, diff: 'Diff') -> Optional[str]:
    file_path = get_diff_file_path(diff, relative=True)
    return get_file_content_from_commit_path(repo, commit, file_path)


def _get_blob_content(blob: Optional['Blob']) -> Optional[str]:
    """Read a diff-side blob's content in-process, with no subprocess spawn.

    `diff.a_blob`/`diff.b_blob` already hold whatever git loaded to compute the patch, so this is
    the same content `git show <ref>:<path>` would return -- for every `Diffable.diff()` variant
    (`index.diff(HEAD, R=True)`, `commit.diff()`, `commit.diff(None)`), `a_blob` is exactly the
    "before" side, and it's `None` precisely when the file didn't exist there (e.g. diffed against
    the empty tree for a brand-new repo/file) -- verified against a scratch repo for each variant.
    """
    if blob is None:
        return None
    return blob.data_stream.read().decode('UTF-8', errors='replace')


def get_commit_range_modified_documents(
    progress_bar: 'BaseProgressBar',
    progress_bar_section: 'ProgressBarSection',
    path: str,
    from_commit_rev: str,
    to_commit_rev: str,
    reverse_diff: bool = True,
) -> tuple[list[Document], list[Document], list[Document]]:
    from_commit_documents = []
    to_commit_documents = []
    diff_documents = []

    repo = git_proxy.get_repo(path)
    diff_index = repo.commit(from_commit_rev).diff(to_commit_rev, create_patch=True, R=reverse_diff)

    modified_files_diff = [
        diff for diff in diff_index if diff.change_type != consts.COMMIT_DIFF_DELETED_FILE_CHANGE_TYPE
    ]
    progress_bar.set_section_length(progress_bar_section, len(modified_files_diff))
    for diff in modified_files_diff:
        progress_bar.update(progress_bar_section)

        file_path = get_path_by_os(get_diff_file_path(diff, repo=repo))

        diff_documents.append(
            Document(
                path=file_path,
                content=get_diff_file_content(diff),
                is_git_diff_format=True,
            )
        )

        file_content = _get_file_content_from_commit_diff(repo, from_commit_rev, diff)
        if file_content is not None:
            from_commit_documents.append(Document(file_path, file_content))

        file_content = _get_file_content_from_commit_diff(repo, to_commit_rev, diff)
        if file_content is not None:
            to_commit_documents.append(Document(file_path, file_content))

    return from_commit_documents, to_commit_documents, diff_documents


def parse_pre_receive_input() -> str:
    """Parse input to pushed branch update details.

    Example input:
    old_value new_value refname
    -----------------------------------------------
    0000000000000000000000000000000000000000 9cf90954ef26e7c58284f8ebf7dcd0fcf711152a refs/heads/main
    973a96d3e925b65941f7c47fa16129f1577d499f 0000000000000000000000000000000000000000 refs/heads/feature-branch
    59564ef68745bca38c42fc57a7822efd519a6bd9 3378e52dcfa47fb11ce3a4a520bea5f85d5d0bf3 refs/heads/develop

    :return: First branch update details (input's first line)
    """
    pre_receive_input = _read_hook_input_from_stdin()
    if not pre_receive_input:
        raise ValueError(
            'Pre receive input was not found. Make sure that you are using this command only in pre-receive hook'
        )

    # each line represents a branch update request, handle the first one only
    # TODO(MichalBor): support case of multiple update branch requests
    return pre_receive_input.splitlines()[0]


def parse_pre_push_input() -> Optional[str]:
    """Parse input to pre-push hook details.

    Example input:
    local_ref local_object_name remote_ref remote_object_name
    ---------------------------------------------------------
    refs/heads/main 9cf90954ef26e7c58284f8ebf7dcd0fcf711152a refs/heads/main 973a96d3e925b65941f7c47fa16129f1577d499f
    refs/heads/feature-branch 3378e52dcfa47fb11ce3a4a520bea5f85d5d0bf3 refs/heads/feature-branch 59564ef68745bca38c42fc57a7822efd519a6bd9

    :return: First push update details (input's first line), or None if no input was provided
    """  # noqa: E501
    pre_push_input = _read_hook_input_from_stdin()
    if not pre_push_input:
        return None

    # each line represents a branch push request, handle the first one only
    return pre_push_input.splitlines()[0]


def is_invoked_by_pre_commit_framework() -> bool:
    return os.getenv(consts.PRE_COMMIT_FRAMEWORK_ENV_VAR_NAME) == '1'


def get_pre_commit_framework_push_range() -> Optional[str]:
    """Get the commit range to scan when invoked as a pre-push hook by the pre-commit framework.

    The pre-commit framework reads git's pre-push stdin itself and never forwards it to hooks.
    Instead, it exposes the already resolved push details via environment variables.

    Returns:
        Commit range string for scanning, or None if not invoked by the pre-commit framework
    """
    from_ref = os.getenv(consts.PRE_COMMIT_FROM_REF_ENV_VAR_NAME)
    to_ref = os.getenv(consts.PRE_COMMIT_TO_REF_ENV_VAR_NAME)
    if from_ref and to_ref:
        return f'{from_ref}..{to_ref}'

    # the framework omits the refs when the pushed history includes the root commit
    if os.getenv(consts.PRE_COMMIT_REMOTE_BRANCH_ENV_VAR_NAME):
        return consts.COMMIT_RANGE_ALL_COMMITS

    return None


def _read_hook_input_from_stdin() -> str:
    """Read input from stdin when called from a hook.

    If called manually from the command line, return an empty string so it doesn't block the main thread.

    Returns:
        Input from stdin
    """
    if sys.stdin.isatty():
        return ''
    return sys.stdin.read().strip()


def _get_default_branches_for_merge_base(repo: 'Repo') -> list[str]:
    """Get a list of default branches to try for merge base calculation.

    Priority order:
    1. Environment variable CYCODE_DEFAULT_BRANCH
    2. Git remote HEAD (git symbolic-ref refs/remotes/origin/HEAD)
    3. Fallback to common default branch names

    Args:
        repo: Git repository object

    Returns:
        List of branch names to try for merge base calculation
    """
    default_branches = []

    # 1. Check environment variable first
    env_default_branch = os.getenv(consts.CYCODE_DEFAULT_BRANCH_ENV_VAR_NAME)
    if env_default_branch:
        logger.debug('Using default branch from environment variable: %s', env_default_branch)
        default_branches.append(env_default_branch)

    # 2. Try to get the actual default branch from remote HEAD
    try:
        remote_head = repo.git.symbolic_ref('refs/remotes/origin/HEAD')
        # symbolic-ref returns something like "refs/remotes/origin/main"
        if remote_head.startswith('refs/remotes/origin/'):
            default_branch = remote_head.replace('refs/remotes/origin/', '')
            logger.debug('Found remote default branch: %s', default_branch)
            # Add both the remote tracking branch and local branch variants
            default_branches.extend([f'origin/{default_branch}', default_branch])
    except Exception as e:
        logger.debug('Failed to get remote HEAD via symbolic-ref: %s', exc_info=e)

        # Try an alternative method: git remote show origin
        try:
            remote_info = repo.git.remote('show', 'origin')
            for line in remote_info.splitlines():
                if 'HEAD branch:' in line:
                    default_branch = line.split('HEAD branch:')[1].strip()
                    logger.debug('Found default branch via remote show: %s', default_branch)
                    default_branches.extend([f'origin/{default_branch}', default_branch])
                    break
        except Exception as e2:
            logger.debug('Failed to get remote info via remote show: %s', exc_info=e2)

    # 3. Add fallback branches (avoiding duplicates)
    fallback_branches = ['origin/main', 'origin/master', 'main', 'master']
    for branch in fallback_branches:
        if branch not in default_branches:
            default_branches.append(branch)

    logger.debug('Default branches to try: %s', default_branches)
    return default_branches


def calculate_pre_push_commit_range(push_update_details: str) -> Optional[str]:
    """Calculate the commit range for pre-push hook scanning.

    Args:
        push_update_details: String in format "local_ref local_object_name remote_ref remote_object_name"

    Returns:
        Commit range string for scanning, or None if no scanning is needed

    Environment Variables:
        CYCODE_DEFAULT_BRANCH: Override the default branch for merge base calculation
    """
    local_ref, local_object_name, remote_ref, remote_object_name = push_update_details.split()

    # Tag pushes don't contain file diffs that need scanning
    if local_ref.startswith('refs/tags/') or remote_ref.startswith('refs/tags/'):
        logger.info('Skipping scan for tag push: %s -> %s', local_ref, remote_ref)
        return None

    # If deleting a ref (local_object_name is all zeros), no need to scan
    if local_object_name == consts.EMPTY_COMMIT_SHA:
        return None

    if remote_object_name == consts.EMPTY_COMMIT_SHA:
        try:
            repo = git_proxy.get_repo(os.getcwd())
            default_branches = _get_default_branches_for_merge_base(repo)

            merge_base = None
            for default_branch in default_branches:
                try:
                    merge_base = repo.git.merge_base(local_object_name, default_branch)
                    logger.debug('Found merge base %s with branch %s', merge_base, default_branch)
                    break
                except Exception as e:
                    logger.debug('Failed to find merge base with %s: %s', default_branch, exc_info=e)
                    continue

            if merge_base:
                return f'{merge_base}..{local_object_name}'

            logger.debug('Failed to find merge base with any default branch')
            return consts.COMMIT_RANGE_ALL_COMMITS
        except Exception as e:
            logger.debug('Failed to get repo for pre-push commit range calculation: %s', exc_info=e)
            return consts.COMMIT_RANGE_ALL_COMMITS

    # For updates to existing branches, scan from remote to local
    return f'{remote_object_name}..{local_object_name}'


def get_diff_file_path(diff: 'Diff', relative: bool = False, repo: Optional['Repo'] = None) -> Optional[str]:
    """Get the file path from a git Diff object.

    Args:
        diff: Git Diff object representing the file change
        relative: If True, return the path relative to the repository root;
            otherwise, return an absolute path IF possible
        repo: Optional Git Repo object, used to resolve absolute paths

    Note:
        It tries to get the absolute path, falling back to relative paths. `relative` flag forces relative paths.

        One case of relative paths is when the repository is bare and does not have a working tree directory.
    """
    # try blob-based paths first (most reliable when available)
    blob = diff.b_blob if diff.b_blob else diff.a_blob
    if blob:
        if relative:
            return blob.path
        if repo and repo.working_tree_dir:
            return blob.abspath

    path = diff.b_path if diff.b_path else diff.a_path  # relative path within the repo
    if not relative and path and repo and repo.working_tree_dir:
        # convert to the absolute path using the repo's working tree directory
        path = os.path.join(repo.working_tree_dir, path)

    return path


def get_diff_file_content(diff: 'Diff') -> str:
    return diff.diff.decode('UTF-8', errors='replace')


def get_pre_commit_modified_documents(
    progress_bar: 'BaseProgressBar',
    progress_bar_section: 'ProgressBarSection',
    repo_path: str,
    base_ref: str = consts.GIT_HEAD_COMMIT_REV,
    include_unstaged: bool = False,
    paths: Optional[list[str]] = None,
    collect_file_contents: bool = True,
) -> tuple[list[Document], list[Document], list[Document]]:
    """Diffs `base_ref` against the staged index (default) or the full working tree.

    Args:
        base_ref: Git ref to diff against. Defaults to HEAD, matching the pre-commit hook's
            historical behavior exactly.
        include_unstaged: If False (default), diffs the staged index only -- this is the exact
            pre-commit hook flow. If True, diffs the full working tree (staged + unstaged).
        paths: Optional pathspec to scope the diff to.
        collect_file_contents: If False, skip building `from_ref_documents`/`working_copy_documents`
            entirely -- only `diff_documents` (the patch itself) is produced. The secret scan path
            only ever uses `diff_documents`, so this avoids a disk read per changed file (and,
            before the `a_blob` fix below, a subprocess spawn per file) that it would otherwise
            discard immediately. Defaults to True so existing callers (SCA/SAST) are unaffected.

    Returns:
        (from_ref_documents, working_copy_documents, diff_documents). `from_ref_documents` holds
        each changed file's content at `base_ref` (skipped if it didn't exist there, or was empty);
        `working_copy_documents` holds each changed file's current on-disk content (skipped if
        the file no longer exists, or is empty); `diff_documents` holds the unified diff per
        changed file.
    """
    from_ref_documents = []
    working_copy_documents = []
    diff_documents = []

    repo = git_proxy.get_repo(repo_path)

    if base_ref == consts.GIT_HEAD_COMMIT_REV and not include_unstaged:
        # The exact pre-commit hook flow, byte-for-byte unchanged: diff the staged index against
        # HEAD (or the empty tree in a brand-new repo), via get_staged_diff_index()'s proven
        # R-flag handling. Keeping this as its own branch (rather than folding it into the
        # `diff_target.diff(...)` calls below) means this default, most-used path can't regress.
        _, diff_index = get_staged_diff_index(repo, paths=paths)
    else:
        try:
            diff_target = repo.commit(base_ref)
        except Exception as e:
            # Repository has no commits yet, or base_ref doesn't resolve; diff against the empty
            # tree instead. (git_proxy.get_null_tree() is only a sentinel usable as the `other`
            # side of a diff, so we resolve the well-known empty tree object itself to diff from.)
            logger.debug(
                'Could not resolve base_ref, falling back to the empty tree, %s', {'base_ref': base_ref}, exc_info=e
            )
            diff_target = repo.tree(consts.GIT_EMPTY_TREE_OBJECT)

        if include_unstaged:
            diff_index = diff_target.diff(None, create_patch=True, paths=paths or None)
        else:
            # `Diffable.diff()` defaults `other` to the staged index, so omitting it here diffs
            # `base_ref` against the index only -- the same "staged changes against an arbitrary
            # ref" semantics as `git diff --cached <base_ref>`, verified to produce identical,
            # correctly-directed patches.
            diff_index = diff_target.diff(create_patch=True, paths=paths or None)

    progress_bar.set_section_length(progress_bar_section, len(diff_index))
    for diff in diff_index:
        progress_bar.update(progress_bar_section)

        file_path = get_path_by_os(get_diff_file_path(diff, repo=repo))

        diff_documents.append(
            Document(
                path=file_path,
                content=get_diff_file_content(diff),
                is_git_diff_format=True,
            )
        )

        if not collect_file_contents:
            continue

        # `a_blob` is exactly the content at `base_ref` -- see `_get_blob_content`'s docstring.
        # Deliberately `if file_content:` (skip empty string) rather than `is not None`: this
        # matches the working_copy branch immediately below, treating an empty file the same as
        # a nonexistent one. `get_commit_range_modified_documents` uses `is not None` instead, but
        # for a different reason (there, `None` only ever means "no such commit"); don't "fix"
        # this one to match it.
        file_content = _get_blob_content(diff.a_blob)
        if file_content:
            from_ref_documents.append(Document(file_path, file_content))

        if os.path.exists(file_path):
            file_content = get_file_content(file_path)
            if file_content:
                working_copy_documents.append(Document(file_path, file_content))

    return from_ref_documents, working_copy_documents, diff_documents


def parse_commit_range(commit_range: str, path: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Parses a git commit range string and returns the full SHAs for the 'from' and 'to' commits.
    Also, it returns the separator in the commit range.

    Supports:
    - 'from..to'
    - 'from...to'
    - 'commit' (interpreted as 'commit..HEAD')
    - '..to' (interpreted as 'HEAD..to')
    - 'from..' (interpreted as 'from..HEAD')
    - '--all' (interpreted as 'first_commit..HEAD' to scan all commits)
    """
    repo = git_proxy.get_repo(path)

    # Handle '--all' special case: scan all commits from first to HEAD
    # Usually represents an empty remote repository
    if commit_range == consts.COMMIT_RANGE_ALL_COMMITS:
        try:
            head_commit = repo.rev_parse(consts.GIT_HEAD_COMMIT_REV).hexsha
            all_commits = repo.git.rev_list('--reverse', head_commit).strip()
            if all_commits:
                first_commit = all_commits.splitlines()[0]
                return first_commit, head_commit, '..'
            logger.warning("No commits found for range '%s'", commit_range)
            return None, None, None
        except Exception as e:
            logger.warning("Failed to parse commit range '%s'", commit_range, exc_info=e)
            return None, None, None

    separator = '..'
    if '...' in commit_range:
        from_spec, to_spec = commit_range.split('...', 1)
        separator = '...'
    elif '..' in commit_range:
        from_spec, to_spec = commit_range.split('..', 1)
    else:
        # Git commands like 'git diff <commit>' compare against HEAD.
        from_spec = commit_range
        to_spec = consts.GIT_HEAD_COMMIT_REV

    # If a spec is empty (e.g., from '..master'), default it to 'HEAD'
    if not from_spec:
        from_spec = consts.GIT_HEAD_COMMIT_REV
    if not to_spec:
        to_spec = consts.GIT_HEAD_COMMIT_REV

    try:
        # Use rev_parse to resolve each specifier to its full commit SHA
        from_commit_rev = repo.rev_parse(from_spec).hexsha
        to_commit_rev = repo.rev_parse(to_spec).hexsha
        return from_commit_rev, to_commit_rev, separator
    except git_proxy.get_git_command_error() as e:
        logger.warning("Failed to parse commit range '%s'", commit_range, exc_info=e)
        return None, None, None


def normalize_commit_range(commit_range: str, path: str) -> str:
    """Normalize a commit range string to handle various formats consistently with all scan types.

    Returns:
        A normalized commit range string suitable for Git operations (e.g., 'full_sha1..full_sha2')
    """
    from_commit_rev, to_commit_rev, separator = parse_commit_range(commit_range, path)
    if from_commit_rev is None or to_commit_rev is None:
        logger.warning('Failed to parse commit range "%s", falling back to raw string.', commit_range)
        return commit_range

    # Construct a normalized range string using the original separator for iter_commits
    normalized_commit_range = f'{from_commit_rev}{separator}{to_commit_rev}'
    logger.debug(
        'Normalized commit range "%s" to "%s"',
        commit_range,
        normalized_commit_range,
    )
    return normalized_commit_range
