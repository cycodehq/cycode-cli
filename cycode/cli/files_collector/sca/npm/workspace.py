import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, Optional

import typer
import yaml

from cycode.cli.utils.path_utils import get_absolute_path, is_sub_path
from cycode.logger import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = get_logger('SCA NPM Workspace')

MANIFEST_FILE_NAME = 'package.json'
PNPM_WORKSPACE_FILE_NAME = 'pnpm-workspace.yaml'

NPM_PACKAGE_MANAGER = 'npm'
YARN_PACKAGE_MANAGER = 'yarn'
PNPM_PACKAGE_MANAGER = 'pnpm'
BUN_PACKAGE_MANAGER = 'bun'
DENO_PACKAGE_MANAGER = 'deno'

NPM_LOCK_FILE_NAME = 'package-lock.json'
NPM_SHRINKWRAP_FILE_NAME = 'npm-shrinkwrap.json'

MANIFEST_DECLARED = 'manifest'
PNPM_WORKSPACE_DECLARED = 'pnpm-workspace'


class RootLockFile(NamedTuple):
    package_manager: str
    file_name: str
    declared_in: str
    requires_lockfile_membership: bool


ROOT_LOCK_FILES = (
    RootLockFile(NPM_PACKAGE_MANAGER, NPM_LOCK_FILE_NAME, MANIFEST_DECLARED, True),
    RootLockFile(NPM_PACKAGE_MANAGER, NPM_SHRINKWRAP_FILE_NAME, MANIFEST_DECLARED, True),
    RootLockFile(YARN_PACKAGE_MANAGER, 'yarn.lock', MANIFEST_DECLARED, False),
    RootLockFile(PNPM_PACKAGE_MANAGER, 'pnpm-lock.yaml', PNPM_WORKSPACE_DECLARED, False),
    RootLockFile(BUN_PACKAGE_MANAGER, 'bun.lock', MANIFEST_DECLARED, False),
    RootLockFile(BUN_PACKAGE_MANAGER, 'bun.lockb', MANIFEST_DECLARED, False),
    RootLockFile(DENO_PACKAGE_MANAGER, 'deno.lock', MANIFEST_DECLARED, False),
)

_LOCKFILE_PACKAGES_SECTION = 'packages'
_MANIFEST_WORKSPACES_SECTION = 'workspaces'
_MANIFEST_WORKSPACE_PACKAGES_SECTION = 'packages'
_PNPM_WORKSPACE_PACKAGES_SECTION = 'packages'
_NODE_MODULES_SEPARATOR = 'node_modules/'
_GIT_DIR_NAME = '.git'
_NEGATION_PREFIX = '!'

_FileStamp = tuple[str, int, int]


class WorkspaceCoverage(NamedTuple):
    package_manager: str
    lock_file: Path


class _WorkspacePatterns(NamedTuple):
    included: tuple[str, ...]
    excluded: tuple[str, ...]


_EMPTY_WORKSPACE_PATTERNS = _WorkspacePatterns((), ())

_npm_member_names_cache: dict[_FileStamp, frozenset[str]] = {}
_workspace_patterns_cache: dict[_FileStamp, _WorkspacePatterns] = {}
_workspace_pattern_regex_cache: dict[str, 're.Pattern[str]'] = {}
_reported_unscanned_roots: set = set()


def clear_cache() -> None:
    _npm_member_names_cache.clear()
    _workspace_patterns_cache.clear()
    _workspace_pattern_regex_cache.clear()
    _reported_unscanned_roots.clear()


def scan_roots_from_context(ctx: typer.Context) -> tuple:
    params = getattr(ctx, 'params', None)
    if not isinstance(params, dict):
        return ()

    path = params.get('path')
    if isinstance(path, str) and path:
        return (path,)

    paths = params.get('paths')
    if isinstance(paths, (list, tuple)):
        return tuple(entry for entry in paths if isinstance(entry, str) and entry)

    return ()


def _file_stamp(path: Path) -> Optional[_FileStamp]:
    try:
        stat_result = path.stat()
    except OSError:
        return None

    return str(path), stat_result.st_mtime_ns, stat_result.st_size


def _read_json_object(path: Path) -> Optional[dict]:
    try:
        content = json.loads(path.read_text(encoding='UTF-8'))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        logger.debug('Could not read an npm workspace file, %s', {'path': str(path), 'error': e})
        return None

    return content if isinstance(content, dict) else None


def _read_yaml_object(path: Path) -> Optional[dict]:
    try:
        content = yaml.safe_load(path.read_text(encoding='UTF-8'))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, yaml.YAMLError) as e:
        logger.debug('Could not read a pnpm workspace file, %s', {'path': str(path), 'error': e})
        return None

    return content if isinstance(content, dict) else None


def _compile_workspace_pattern(pattern: str) -> 're.Pattern[str]':
    compiled = _workspace_pattern_regex_cache.get(pattern)
    if compiled is not None:
        return compiled

    parts = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == '*' and pattern[index + 1 : index + 2] == '*':
            parts.append('.*')
            index += 2
        elif character == '*':
            parts.append('[^/]*')
            index += 1
        elif character == '?':
            parts.append('[^/]')
            index += 1
        else:
            parts.append(re.escape(character))
            index += 1

    compiled = re.compile(''.join(parts))
    _workspace_pattern_regex_cache[pattern] = compiled
    return compiled


def _split_workspace_patterns(declared: list) -> _WorkspacePatterns:
    included = []
    excluded = []
    for entry in declared:
        stripped = entry.strip()
        is_excluded = stripped.startswith(_NEGATION_PREFIX)
        normalized = (stripped[1:] if is_excluded else stripped).strip()
        if normalized.startswith('./'):
            normalized = normalized[2:]

        normalized = normalized.rstrip('/')
        if not normalized:
            continue

        if is_excluded:
            excluded.append(normalized)
        else:
            included.append(normalized)

    return _WorkspacePatterns(tuple(included), tuple(excluded))


def _read_manifest_workspace_patterns(root_dir: Path) -> _WorkspacePatterns:
    manifest = root_dir / MANIFEST_FILE_NAME
    stamp = _file_stamp(manifest)
    if stamp is None:
        return _EMPTY_WORKSPACE_PATTERNS

    cached = _workspace_patterns_cache.get(stamp)
    if cached is not None:
        return cached

    content = _read_json_object(manifest)
    workspaces = content.get(_MANIFEST_WORKSPACES_SECTION) if content is not None else None
    if isinstance(workspaces, dict):
        workspaces = workspaces.get(_MANIFEST_WORKSPACE_PACKAGES_SECTION)

    declared = [entry for entry in workspaces if isinstance(entry, str)] if isinstance(workspaces, list) else []
    patterns = _split_workspace_patterns(declared)
    _workspace_patterns_cache[stamp] = patterns
    return patterns


def _read_pnpm_workspace_patterns(root_dir: Path) -> _WorkspacePatterns:
    pnpm_workspace = root_dir / PNPM_WORKSPACE_FILE_NAME
    stamp = _file_stamp(pnpm_workspace)
    if stamp is None:
        return _EMPTY_WORKSPACE_PATTERNS

    cached = _workspace_patterns_cache.get(stamp)
    if cached is not None:
        return cached

    content = _read_yaml_object(pnpm_workspace)
    packages = content.get(_PNPM_WORKSPACE_PACKAGES_SECTION) if content is not None else None

    declared = [entry for entry in packages if isinstance(entry, str)] if isinstance(packages, list) else []
    patterns = _split_workspace_patterns(declared)
    _workspace_patterns_cache[stamp] = patterns
    return patterns


def _declares_workspace_member(root_dir: Path, member_path: str, declared_in: str) -> bool:
    if declared_in == PNPM_WORKSPACE_DECLARED:
        patterns = _read_pnpm_workspace_patterns(root_dir)
    else:
        patterns = _read_manifest_workspace_patterns(root_dir)

    if not any(_compile_workspace_pattern(pattern).fullmatch(member_path) for pattern in patterns.included):
        return False

    return not any(_compile_workspace_pattern(pattern).fullmatch(member_path) for pattern in patterns.excluded)


def _npm_lockfile_member_names(lock_file: Path) -> frozenset:
    stamp = _file_stamp(lock_file)
    if stamp is None:
        return frozenset()

    cached = _npm_member_names_cache.get(stamp)
    if cached is not None:
        return cached

    content = _read_json_object(lock_file)
    packages = content.get(_LOCKFILE_PACKAGES_SECTION) if content is not None else None
    member_names = (
        frozenset(name for name in packages if name and _NODE_MODULES_SEPARATOR not in name)
        if isinstance(packages, dict)
        else frozenset()
    )

    _npm_member_names_cache[stamp] = member_names
    return member_names


def _containing_scan_roots(manifest_dir: Path, scan_roots: tuple) -> list:
    absolute_manifest_dir = get_absolute_path(str(manifest_dir))
    return [
        Path(get_absolute_path(scan_root))
        for scan_root in scan_roots
        if is_sub_path(get_absolute_path(scan_root), absolute_manifest_dir)
    ]


def _resolve_walk_boundary(manifest_dir: Path, scan_roots: tuple) -> Optional[Path]:
    for root_dir in manifest_dir.parents:
        if (root_dir / _GIT_DIR_NAME).exists():
            return root_dir

    containing = _containing_scan_roots(manifest_dir, scan_roots)
    if containing:
        return min(containing, key=lambda scan_root: len(scan_root.parts))

    return None


def _workspace_root_candidates(manifest_dir: Path, scan_roots: tuple) -> 'Iterator[Path]':
    boundary = _resolve_walk_boundary(manifest_dir, scan_roots)
    absolute_boundary = get_absolute_path(str(boundary)) if boundary is not None else None
    if absolute_boundary == get_absolute_path(str(manifest_dir)):
        return

    for root_dir in manifest_dir.parents:
        yield root_dir
        if absolute_boundary is not None and get_absolute_path(str(root_dir)) == absolute_boundary:
            return


def _find_covering_workspace(manifest_dir: Path, scan_roots: tuple) -> Optional[WorkspaceCoverage]:
    for root_dir in _workspace_root_candidates(manifest_dir, scan_roots):
        member_path = manifest_dir.relative_to(root_dir).as_posix()

        for root_lock_file in ROOT_LOCK_FILES:
            lock_file = root_dir / root_lock_file.file_name
            if not lock_file.is_file():
                continue

            if not _declares_workspace_member(root_dir, member_path, root_lock_file.declared_in):
                continue

            if root_lock_file.requires_lockfile_membership and member_path not in _npm_lockfile_member_names(lock_file):
                continue

            return WorkspaceCoverage(root_lock_file.package_manager, lock_file)

    return None


def find_covering_workspace(manifest_dir: Optional[str], scan_roots: tuple = ()) -> Optional[WorkspaceCoverage]:
    if not manifest_dir:
        return None

    return _find_covering_workspace(Path(manifest_dir), scan_roots)


def _is_inside_scanned_paths(scan_roots: tuple, root_dir: Path) -> bool:
    if not scan_roots:
        return True

    absolute_root_dir = get_absolute_path(str(root_dir))
    return any(is_sub_path(get_absolute_path(scan_root), absolute_root_dir) for scan_root in scan_roots)


def is_covered_workspace_member(manifest_dir: Optional[str], document_path: str, scan_roots: tuple = ()) -> bool:
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
            'Skipping restore for a workspace member whose root is outside the scanned path. '
            'Scan the workspace root to collect its dependencies, %s',
            details,
        )

    return True
