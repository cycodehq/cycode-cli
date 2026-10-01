import os
from pathlib import Path
from typing import Annotated, Optional

import typer

from cycode.cli import consts
from cycode.cli.apps.scan.commit_range_scanner import scan_pre_commit
from cycode.cli.exceptions.custom_exceptions import ScanPathOutsideRepositoryError, UnresolvedGitRefError
from cycode.cli.exceptions.handle_scan_errors import handle_scan_exception
from cycode.cli.logger import logger
from cycode.cli.utils.git_proxy import git_proxy


def _resolve_repo_root(cwd: str) -> str:
    """Resolve the repository root from `cwd`, which may be any subdirectory of the repo.

    `git_proxy.get_repo()` requires an exact match (the root or a `.git` dir) unless told to
    search parent directories, so without this, running the command from anywhere but the repo
    root raises a misleading "not a git repository" error. The git pre-commit hook framework
    always invokes from the repo root, so this is a no-op there; it matters for IDE-style
    invocations (--include-unstaged etc.), which may run from any subdirectory.
    """
    repo = git_proxy.get_repo(cwd, search_parent_directories=True)
    return repo.working_tree_dir or cwd


def _validate_base_ref(repo_path: str, base_ref: str) -> None:
    """Raise a clear, user-facing error for an unresolvable `--base-ref`.

    A repository with no commits at all is a valid state (the diff falls back to comparing
    against the empty tree), so validation is skipped in that case.
    """
    repo = git_proxy.get_repo(repo_path)

    try:
        repo.rev_parse(consts.GIT_HEAD_COMMIT_REV)
    except Exception as e:
        logger.debug('Repository has no commits yet; skipping --base-ref validation', exc_info=e)
        return

    try:
        repo.commit(base_ref)
    except Exception as e:
        raise UnresolvedGitRefError(base_ref) from e


def pre_commit_command(
    ctx: typer.Context,
    _: Annotated[Optional[list[str]], typer.Argument(help='Ignored arguments', hidden=True)] = None,
    base_ref: Annotated[
        str,
        typer.Option(
            '--base-ref',
            '-b',
            help='Git ref (commit, branch, or tag) to diff against. Defaults to HEAD, matching the '
            'pre-commit hook behavior. Combine with --include-unstaged for IDE-style local diff scanning.',
        ),
    ] = consts.GIT_HEAD_COMMIT_REV,
    include_unstaged: Annotated[
        bool,
        typer.Option(
            '--include-unstaged',
            help='Also scan unstaged changes to tracked files, not just what is staged. '
            'Off by default, so the pre-commit hook flow is unaffected.',
        ),
    ] = False,
    paths: Annotated[
        Optional[list[Path]],
        typer.Option(
            '--path',
            help='Optional paths to scope the diff scan to (e.g. the file currently open in an IDE). '
            'Defaults to the entire working directory. Repeatable.',
            show_default=False,
            resolve_path=True,
        ),
    ] = None,
) -> None:
    try:
        repo_path = _resolve_repo_root(os.getcwd())
        _validate_base_ref(repo_path, base_ref)
        str_paths = [str(path) for path in paths] if paths else None
        # realpath both sides: repo_path (from GitPython) and str_path (from Click's
        # resolve_path=True) can disagree on 8.3 short-name vs long-name form on Windows,
        # which would otherwise make an in-repo path look like it's outside the repo.
        repo_path_real = os.path.realpath(repo_path)
        for str_path in str_paths or []:
            if os.path.commonpath([repo_path_real, os.path.realpath(str_path)]) != repo_path_real:
                raise ScanPathOutsideRepositoryError(str_path, repo_path)
    except Exception as e:
        handle_scan_exception(ctx, e)
        return

    progress_bar = ctx.obj['progress_bar']
    progress_bar.start()

    try:
        scan_pre_commit(ctx, repo_path, base_ref=base_ref, include_unstaged=include_unstaged, paths=str_paths)
    except Exception as e:
        handle_scan_exception(ctx, e)
