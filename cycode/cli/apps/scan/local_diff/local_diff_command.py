import os
from pathlib import Path
from typing import Annotated, Optional

import typer

from cycode.cli import consts
from cycode.cli.apps.scan.commit_range_scanner import scan_local_diff
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.logger import logger
from cycode.cli.utils.git_proxy import git_proxy


def _resolve_repo_root(cwd: str) -> str:
    """Resolve the repository root from `cwd`, which may be any subdirectory of the repo.

    `git_proxy.get_repo()` requires an exact match (the root or a `.git` dir) unless told to
    search parent directories, so without this, running the command from anywhere but the
    repo root raises a misleading "not a git repository" error.
    """
    repo = git_proxy.get_repo(cwd, search_parent_directories=True)
    return repo.working_tree_dir or cwd


def _validate_commit_ref(repo_path: str, commit: str) -> None:
    """Raise a clear, user-facing error for an unresolvable `--commit` ref.

    A repository with no commits at all is a valid state (the diff falls back to comparing
    against the empty tree), so validation is skipped in that case.
    """
    repo = git_proxy.get_repo(repo_path)

    try:
        repo.rev_parse(consts.GIT_HEAD_COMMIT_REV)
    except Exception as e:
        logger.debug('Repository has no commits yet; skipping --commit validation', exc_info=e)
        return

    try:
        repo.commit(commit)
    except Exception as e:
        raise typer.BadParameter(f'Could not resolve git ref: {commit!r}', param_hint='--commit') from e


def local_diff_command(
    ctx: typer.Context,
    paths: Annotated[
        Optional[list[Path]],
        typer.Argument(
            help='Optional paths to scope the diff scan to (e.g. the file currently open in an IDE). '
            'Defaults to the entire working directory.',
            show_default=False,
            resolve_path=True,
        ),
    ] = None,
    commit: Annotated[
        str,
        typer.Option(
            '--commit',
            '-c',
            help='Git ref (commit, branch, or tag) to diff against. '
            'Compares this ref to the current staged, unstaged, and untracked changes in the working directory.',
        ),
    ] = 'HEAD',
) -> None:
    try:
        repo_path = _resolve_repo_root(os.getcwd())
        _validate_commit_ref(repo_path, commit)
    except typer.BadParameter:
        raise
    except Exception as e:
        handle_scan_exception(ctx, e)
        return

    logger.debug('Starting local diff scan process, %s', {'commit': commit, 'paths': paths})

    try:
        str_paths = [str(path) for path in paths] if paths else None
        scan_local_diff(ctx, repo_path=repo_path, commit_rev=commit, paths=str_paths)
    except Exception as e:
        handle_scan_exception(ctx, e)
