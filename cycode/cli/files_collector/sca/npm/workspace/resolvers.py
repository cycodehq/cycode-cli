"""Reading the members a root lockfile resolves, one reader per lockfile format.

A reader that returns a set is the authority on that lockfile, including when the set is empty.
None means the format cannot name its members at all, and only then does may_use_workspace_globs
decide whether the manifest globs get a say.
"""

import json
import re
from abc import ABC, abstractmethod
from pathlib import Path

import yaml

from cycode.cli.files_collector.sca.npm.workspace.files import FileStamp, file_stamp, logger, read_json_object
from cycode.cli.files_collector.sca.npm.workspace.names import (
    BUN_BINARY_LOCK_FILE_NAME,
    BUN_LOCK_FILE_NAME,
    BUN_PACKAGE_MANAGER,
    NPM_LOCK_FILE_NAME,
    NPM_PACKAGE_MANAGER,
    NPM_SHRINKWRAP_FILE_NAME,
    PNPM_LOCK_FILE_NAME,
    PNPM_PACKAGE_MANAGER,
    YARN_LOCK_FILE_NAME,
    YARN_PACKAGE_MANAGER,
)

_LOCKFILE_PACKAGES_SECTION = 'packages'
_NODE_MODULES_SEPARATOR = 'node_modules/'
_PNPM_LOCKFILE_IMPORTERS_SECTION = 'importers'
_PNPM_LOCKFILE_ROOT_IMPORTER = '.'
_YAML_COMMENT_PREFIX = '#'
_YARN_BERRY_MARKER = '__metadata'
_YARN_RESOLUTION_PREFIX = 'resolution:'
_YARN_WORKSPACE_PROTOCOL = re.compile(r'@workspace:([^"\',\s]+)')
_BUN_LOCKFILE_WORKSPACES_SECTION = 'workspaces'
_TRAILING_COMMA = re.compile(r',(\s*[}\]])')

_member_names_cache: dict[FileStamp, frozenset[str] | None] = {}


def clear_cache() -> None:
    _member_names_cache.clear()


def _normalize_member_path(member_path: str) -> str | None:
    normalized = member_path.strip()
    normalized = normalized.removeprefix('./')

    normalized = normalized.rstrip('/')
    if not normalized or normalized == _PNPM_LOCKFILE_ROOT_IMPORTER:
        return None

    return normalized


def _npm_lockfile_member_names(lock_file: Path) -> frozenset | None:
    content = read_json_object(lock_file)
    packages = content.get(_LOCKFILE_PACKAGES_SECTION) if content is not None else None
    if not isinstance(packages, dict):
        return None

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


def _pnpm_lockfile_member_names(lock_file: Path) -> frozenset | None:
    section = _read_pnpm_importers_section(lock_file)
    if not section:
        return None

    try:
        content = yaml.safe_load(section)
    except (ValueError, yaml.YAMLError) as e:
        logger.debug('Could not read a pnpm lockfile, %s', {'path': str(lock_file), 'error': e})
        return None

    importers = content.get(_PNPM_LOCKFILE_IMPORTERS_SECTION) if isinstance(content, dict) else None
    if not isinstance(importers, dict):
        return None

    member_names = set()
    for name in importers:
        if not isinstance(name, str):
            continue

        normalized = _normalize_member_path(name)
        if normalized:
            member_names.add(normalized)

    # a lockfile whose only importer is the root describes a single package, not a workspace
    return frozenset(member_names) or None


def _bun_lockfile_member_names(lock_file: Path) -> frozenset | None:
    """bun.lock is JSON with trailing commas, and names its members under "workspaces"."""
    try:
        text = lock_file.read_text(encoding='UTF-8')
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        logger.debug('Could not read a bun lockfile, %s', {'path': str(lock_file), 'error': e})
        return None

    try:
        content = json.loads(text)
    except ValueError:
        try:
            content = json.loads(_TRAILING_COMMA.sub(r'\1', text))
        except ValueError as e:
            logger.debug('Could not read a bun lockfile, %s', {'path': str(lock_file), 'error': e})
            return None

    workspaces = content.get(_BUN_LOCKFILE_WORKSPACES_SECTION) if isinstance(content, dict) else None
    if not isinstance(workspaces, dict):
        return None

    member_names = {normalized for normalized in map(_normalize_member_path, workspaces) if normalized}
    return frozenset(member_names)


def _yarn_lockfile_member_names(lock_file: Path) -> frozenset | None:
    """Yarn berry records every member as "<name>@workspace:<path>"; classic yarn records nothing."""
    try:
        text = lock_file.read_text(encoding='UTF-8', errors='replace')
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        logger.debug('Could not read a yarn lockfile, %s', {'path': str(lock_file), 'error': e})
        return None

    if _YARN_BERRY_MARKER not in text:
        return None  # classic: flat, so the manifest globs are the only remaining source

    member_names = set()
    for line in text.splitlines():
        # every entry carries a resolution naming its real path; the dependency entries carry
        # ranges instead (workspace:^, workspace:*), which are not paths
        if not line.strip().startswith(_YARN_RESOLUTION_PREFIX):
            continue

        for declared_path in _YARN_WORKSPACE_PROTOCOL.findall(line):
            normalized = _normalize_member_path(declared_path)
            if normalized:
                member_names.add(normalized)

    # berry always records what it installed, so an empty result means this is not a workspace
    return frozenset(member_names)


class WorkspaceMemberResolver(ABC):
    """Reads, from one root lockfile, the member directories that lockfile resolves."""

    @property
    @abstractmethod
    def package_manager(self) -> str: ...

    @property
    @abstractmethod
    def lock_file_names(self) -> tuple: ...

    @property
    def may_use_workspace_globs(self) -> bool:
        """Whether an unanswerable lockfile may defer to the manifest's workspaces globs.

        False means the silence is itself an answer: a v1 package-lock predates workspaces, so
        its root is simply not one. True means the format has workspaces but does not record
        them, leaving the globs as the only remaining source.
        """
        return False

    def resolve(self, lock_file: Path) -> frozenset | None:
        """Member paths this lockfile resolves, or None when it cannot name them.

        Caches on the file's identity so one scan parses each root lockfile once.
        """
        stamp = file_stamp(lock_file)
        if stamp is None:
            return None

        if stamp in _member_names_cache:
            return _member_names_cache[stamp]

        member_names = self._read_member_names(lock_file)
        _member_names_cache[stamp] = member_names
        return member_names

    @abstractmethod
    def _read_member_names(self, lock_file: Path) -> frozenset | None: ...


class NpmLockfileResolver(WorkspaceMemberResolver):
    package_manager = NPM_PACKAGE_MANAGER
    lock_file_names = (NPM_LOCK_FILE_NAME, NPM_SHRINKWRAP_FILE_NAME)

    def _read_member_names(self, lock_file: Path) -> frozenset | None:
        return _npm_lockfile_member_names(lock_file)


class PnpmLockfileResolver(WorkspaceMemberResolver):
    package_manager = PNPM_PACKAGE_MANAGER
    lock_file_names = (PNPM_LOCK_FILE_NAME,)

    def _read_member_names(self, lock_file: Path) -> frozenset | None:
        return _pnpm_lockfile_member_names(lock_file)


class YarnLockfileResolver(WorkspaceMemberResolver):
    """Berry names every member; classic is flat and names none, so only classic needs the globs."""

    package_manager = YARN_PACKAGE_MANAGER
    lock_file_names = (YARN_LOCK_FILE_NAME,)
    may_use_workspace_globs = True

    def _read_member_names(self, lock_file: Path) -> frozenset | None:
        return _yarn_lockfile_member_names(lock_file)


class BunLockfileResolver(WorkspaceMemberResolver):
    """Only the text bun.lock names members; the binary bun.lockb is handled as opaque."""

    package_manager = BUN_PACKAGE_MANAGER
    lock_file_names = (BUN_LOCK_FILE_NAME,)

    def _read_member_names(self, lock_file: Path) -> frozenset | None:
        return _bun_lockfile_member_names(lock_file)


class OpaqueLockfileResolver(WorkspaceMemberResolver):
    """A lockfile we cannot read members from at all, so the manifest globs decide."""

    may_use_workspace_globs = True

    def __init__(self, package_manager: str, lock_file_names: tuple) -> None:
        self._package_manager = package_manager
        self._lock_file_names = lock_file_names

    @property
    def package_manager(self) -> str:
        return self._package_manager

    @property
    def lock_file_names(self) -> tuple:
        return self._lock_file_names

    def _read_member_names(self, lock_file: Path) -> frozenset | None:
        return None


# Order is precedence: the first lockfile that resolves the member wins.
#
# deno.lock is deliberately absent. The glob fallback reads the manifest's workspaces field,
# which deno does not use - it declares members in deno.json - so a match there would be
# meaningless. A deno.lock beside a manifest still stops the npm fallback, through the
# alternative-lockfile guard in the npm handler.
MEMBER_RESOLVERS = (
    NpmLockfileResolver(),
    YarnLockfileResolver(),
    PnpmLockfileResolver(),
    BunLockfileResolver(),
    OpaqueLockfileResolver(BUN_PACKAGE_MANAGER, (BUN_BINARY_LOCK_FILE_NAME,)),
)
