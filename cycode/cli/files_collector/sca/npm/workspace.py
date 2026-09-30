import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, Optional

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
YARN_LOCK_FILE_NAME = 'yarn.lock'
PNPM_LOCK_FILE_NAME = 'pnpm-lock.yaml'
BUN_LOCK_FILE_NAME = 'bun.lock'
BUN_BINARY_LOCK_FILE_NAME = 'bun.lockb'
DENO_LOCK_FILE_NAME = 'deno.lock'

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
    RootLockFile(YARN_PACKAGE_MANAGER, YARN_LOCK_FILE_NAME, MANIFEST_DECLARED, False),
    RootLockFile(PNPM_PACKAGE_MANAGER, PNPM_LOCK_FILE_NAME, PNPM_WORKSPACE_DECLARED, True),
    RootLockFile(BUN_PACKAGE_MANAGER, BUN_LOCK_FILE_NAME, MANIFEST_DECLARED, False),
    RootLockFile(BUN_PACKAGE_MANAGER, BUN_BINARY_LOCK_FILE_NAME, MANIFEST_DECLARED, False),
    RootLockFile(DENO_PACKAGE_MANAGER, DENO_LOCK_FILE_NAME, MANIFEST_DECLARED, False),
)

_LOCKFILE_PACKAGES_SECTION = 'packages'
_MANIFEST_WORKSPACES_SECTION = 'workspaces'
_MANIFEST_WORKSPACE_PACKAGES_SECTION = 'packages'
_PNPM_WORKSPACE_PACKAGES_SECTION = 'packages'
_PNPM_LOCKFILE_IMPORTERS_SECTION = 'importers'
_PNPM_LOCKFILE_ROOT_IMPORTER = '.'
_NODE_MODULES_SEPARATOR = 'node_modules/'
_GIT_DIR_NAME = '.git'
_NEGATION_PREFIX = '!'
_YAML_COMMENT_PREFIX = '#'

_FileStamp = tuple[str, int, int]


class WorkspaceCoverage(NamedTuple):
    package_manager: str
    lock_file: Path


class _WorkspacePatterns(NamedTuple):
    included: tuple[str, ...]
    excluded: tuple[str, ...]


_EMPTY_WORKSPACE_PATTERNS = _WorkspacePatterns((), ())

_member_names_cache: dict[_FileStamp, frozenset[str]] = {}
_workspace_patterns_cache: dict[_FileStamp, _WorkspacePatterns] = {}
_workspace_pattern_regex_cache: dict[str, 're.Pattern[str]'] = {}
_reported_unscanned_roots: set = set()


def clear_cache() -> None:
    _member_names_cache.clear()
    _workspace_patterns_cache.clear()
    _workspace_pattern_regex_cache.clear()
    _reported_unscanned_roots.clear()


def _resolved_path(path: object) -> str:
    return os.path.realpath(get_absolute_path(str(path)))


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
    content = _read_json_object(lock_file)
    packages = content.get(_LOCKFILE_PACKAGES_SECTION) if content is not None else None
    if not isinstance(packages, dict):
        return frozenset()

    return frozenset(name for name in packages if name and _NODE_MODULES_SEPARATOR not in name)


def _read_pnpm_importers_section(lock_file: Path) -> str:
    """Slice out the top-level importers block so a large lockfile is not parsed in full."""
    section = []
    inside = False
    try:
        with lock_file.open(encoding='UTF-8') as lock_file_lines:
            for raw_line in lock_file_lines:
                line = raw_line.rstrip('\n').rstrip('\r')
                if not inside:
                    if line.startswith(f'{_PNPM_LOCKFILE_IMPORTERS_SECTION}:'):
                        inside = True
                        section.append(line)
                    continue

                if line.startswith(_YAML_COMMENT_PREFIX):
                    continue

                if line and not line[0].isspace():
                    break

                section.append(line)
    except FileNotFoundError:
        return ''
    except (OSError, ValueError) as e:
        logger.debug('Could not read a pnpm lockfile, %s', {'path': str(lock_file), 'error': e})
        return ''

    return '\n'.join(section)


def _pnpm_lockfile_member_names(lock_file: Path) -> frozenset:
    section = _read_pnpm_importers_section(lock_file)
    if not section:
        return frozenset()

    try:
        content = yaml.safe_load(section)
    except (ValueError, yaml.YAMLError) as e:
        logger.debug('Could not read a pnpm lockfile, %s', {'path': str(lock_file), 'error': e})
        return frozenset()

    importers = content.get(_PNPM_LOCKFILE_IMPORTERS_SECTION) if isinstance(content, dict) else None
    if not isinstance(importers, dict):
        return frozenset()

    member_names = set()
    for name in importers:
        if not isinstance(name, str):
            continue

        normalized = _normalize_member_path(name)
        if normalized:
            member_names.add(normalized)

    return frozenset(member_names)


def _normalize_member_path(member_path: str) -> Optional[str]:
    normalized = member_path.strip()
    if normalized.startswith('./'):
        normalized = normalized[2:]

    normalized = normalized.rstrip('/')
    if not normalized or normalized == _PNPM_LOCKFILE_ROOT_IMPORTER:
        return None

    return normalized


def _lockfile_member_names(lock_file: Path, package_manager: str) -> frozenset:
    stamp = _file_stamp(lock_file)
    if stamp is None:
        return frozenset()

    cached = _member_names_cache.get(stamp)
    if cached is not None:
        return cached

    if package_manager == PNPM_PACKAGE_MANAGER:
        member_names = _pnpm_lockfile_member_names(lock_file)
    else:
        member_names = _npm_lockfile_member_names(lock_file)

    _member_names_cache[stamp] = member_names
    return member_names


def _scan_root_directories(scan_roots: tuple) -> list:
    """The directory each scanned path stands for; scanning a file scans its directory."""
    directories = []
    for scan_root in scan_roots:
        resolved = _resolved_path(scan_root)
        if os.path.isfile(resolved):
            resolved = os.path.dirname(resolved)

        if resolved:
            directories.append(resolved)

    return directories


def _containing_scan_roots(manifest_dir: Path, scan_roots: tuple) -> list:
    resolved_manifest_dir = _resolved_path(manifest_dir)
    return [
        Path(directory)
        for directory in _scan_root_directories(scan_roots)
        if is_sub_path(directory, resolved_manifest_dir)
    ]


def _resolve_walk_boundary(manifest_dir: Path, scan_roots: tuple) -> Optional[Path]:
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
    resolved_boundary = _resolved_path(boundary) if boundary is not None else None
    if resolved_boundary == _resolved_path(manifest_dir):
        return

    for root_dir in manifest_dir.parents:
        yield root_dir
        if resolved_boundary is not None and _resolved_path(root_dir) == resolved_boundary:
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

            if root_lock_file.requires_lockfile_membership and member_path not in _lockfile_member_names(
                lock_file, root_lock_file.package_manager
            ):
                continue

            return WorkspaceCoverage(root_lock_file.package_manager, lock_file)

    return None


def find_covering_workspace(manifest_dir: Optional[str], scan_roots: tuple = ()) -> Optional[WorkspaceCoverage]:
    if not manifest_dir:
        return None

    return _find_covering_workspace(Path(manifest_dir), scan_roots)


def _is_inside_scanned_paths(scan_roots: tuple, root_dir: Path) -> bool:
    directories = _scan_root_directories(scan_roots)
    if not directories:
        logger.debug('No scanned paths in context; treating the workspace root as scanned, %s', {'root': str(root_dir)})
        return True

    resolved_root_dir = _resolved_path(root_dir)
    return any(is_sub_path(directory, resolved_root_dir) for directory in directories)


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
            'The workspace root lockfile is outside the scanned path and will not be collected, '
            'so this member is restored on its own. Scan the workspace root for the versions it '
            'actually installs, %s',
            details,
        )

    return False
