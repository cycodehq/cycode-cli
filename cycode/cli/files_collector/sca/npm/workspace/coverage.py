"""Walking up from a manifest to the lockfile that already resolves it."""

import os
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

from cycode.cli.files_collector.sca.npm.workspace.files import logger, resolved_path
from cycode.cli.files_collector.sca.npm.workspace.globs import declares_workspace_member
from cycode.cli.files_collector.sca.npm.workspace.resolvers import MEMBER_RESOLVERS
from cycode.cli.utils.path_utils import is_sub_path

if TYPE_CHECKING:
    from collections.abc import Iterator

_GIT_DIR_NAME = '.git'

_reported_unscanned_roots: set = set()


def clear_cache() -> None:
    _reported_unscanned_roots.clear()


class WorkspaceCoverage(NamedTuple):
    package_manager: str
    lock_file: Path


def _scan_root_directories(scan_roots: tuple) -> list:
    """The directory each scanned path stands for; scanning a file scans its directory."""
    directories = []
    for scan_root in scan_roots:
        resolved = resolved_path(scan_root)
        if os.path.isfile(resolved):
            resolved = os.path.dirname(resolved)

        if resolved:
            directories.append(resolved)

    return directories


def _containing_scan_roots(manifest_dir: Path, scan_roots: tuple) -> list:
    resolved_manifest_dir = resolved_path(manifest_dir)
    return [
        Path(directory)
        for directory in _scan_root_directories(scan_roots)
        if is_sub_path(directory, resolved_manifest_dir)
    ]


def _resolve_walk_boundary(manifest_dir: Path, scan_roots: tuple) -> Path | None:
    for root_dir in manifest_dir.parents:
        if (root_dir / _GIT_DIR_NAME).exists():
            return root_dir

    containing = _containing_scan_roots(manifest_dir, scan_roots)
    if containing:
        return min(containing, key=lambda scan_root: len(scan_root.parts))

    if scan_roots:
        return manifest_dir

    return None


def _workspace_root_candidates(manifest_dir: Path, scan_roots: tuple) -> 'Iterator[Path]':
    boundary = _resolve_walk_boundary(manifest_dir, scan_roots)
    resolved_boundary = resolved_path(boundary) if boundary is not None else None
    if resolved_boundary == resolved_path(manifest_dir):
        return

    for root_dir in manifest_dir.parents:
        yield root_dir
        if resolved_boundary is not None and resolved_path(root_dir) == resolved_boundary:
            return


def _find_covering_workspace(manifest_dir: Path, scan_roots: tuple) -> WorkspaceCoverage | None:
    for root_dir in _workspace_root_candidates(manifest_dir, scan_roots):
        member_path = manifest_dir.relative_to(root_dir).as_posix()

        for resolver in MEMBER_RESOLVERS:
            for lock_file_name in resolver.lock_file_names:
                lock_file = root_dir / lock_file_name
                if not lock_file.is_file():
                    continue

                member_names = resolver.resolve(lock_file)
                if member_names is not None:
                    if member_path in member_names:
                        return WorkspaceCoverage(resolver.package_manager, lock_file)
                    continue

                if resolver.may_use_workspace_globs and declares_workspace_member(root_dir, member_path):
                    return WorkspaceCoverage(resolver.package_manager, lock_file)

    return None


def find_covering_workspace(manifest_dir: str | None, scan_roots: tuple = ()) -> WorkspaceCoverage | None:
    if not manifest_dir:
        return None

    return _find_covering_workspace(Path(manifest_dir), scan_roots)


def _is_inside_scanned_paths(scan_roots: tuple, root_dir: Path) -> bool:
    directories = _scan_root_directories(scan_roots)
    if not directories:
        logger.debug('No scanned paths in context; treating the workspace root as scanned, %s', {'root': str(root_dir)})
        return True

    resolved_root_dir = resolved_path(root_dir)
    return any(is_sub_path(directory, resolved_root_dir) for directory in directories)


def is_covered_workspace_member(manifest_dir: str | None, document_path: str, scan_roots: tuple = ()) -> bool:
    coverage = find_covering_workspace(manifest_dir, scan_roots)
    if coverage is None:
        return False

    details = {
        'path': document_path,
        'root_lockfile': str(coverage.lock_file),
        'workspace': coverage.package_manager,
    }
    if _is_inside_scanned_paths(scan_roots, coverage.lock_file.parent):
        logger.debug('Skipping restore: the workspace root lockfile already covers this member, %s', details)
        return True

    report_key = (document_path, str(coverage.lock_file))
    if report_key not in _reported_unscanned_roots:
        _reported_unscanned_roots.add(report_key)
        logger.warning(
            'The workspace root lockfile is outside the scanned path and will not be collected, '
            'so this member is restored on its own. Scan the workspace root for the versions it '
            'actually installs, %s',
            details,
        )

    return False
