import json
import re
from pathlib import Path
from typing import Optional

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document
from cycode.logger import get_logger

logger = get_logger('NPM Restore Dependencies')

NPM_MANIFEST_FILE_NAME = 'package.json'
NPM_LOCK_FILE_NAME = 'package-lock.json'
NPM_SHRINKWRAP_FILE_NAME = 'npm-shrinkwrap.json'
# npm resolves a workspace from either of these at the root; npm shrinkwrap just renames the lockfile.
_WORKSPACE_ROOT_LOCK_FILES = (NPM_LOCK_FILE_NAME, NPM_SHRINKWRAP_FILE_NAME)
# These lockfiles indicate another package manager owns the project — NPM should not run
_ALTERNATIVE_LOCK_FILES = ('yarn.lock', 'pnpm-lock.yaml', 'deno.lock', 'bun.lock')
# npm records every workspace member as a key of the lockfile's "packages" object, relative to the
# lockfile's own directory. The root is the empty key and installed packages live under "node_modules/".
_LOCKFILE_PACKAGES_SECTION = 'packages'
_NODE_MODULES_SEPARATOR = 'node_modules/'
_MANIFEST_WORKSPACES_SECTION = 'workspaces'
_MANIFEST_WORKSPACE_PACKAGES_SECTION = 'packages'


class RestoreNpmDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        """Match only package.json files that are not managed by Yarn or pnpm.

        Yarn and pnpm projects are handled by their dedicated handlers, which run before
        this one in the handler list. This handler is the npm fallback.

        NOTE: this guard only excludes a project when an alternative lockfile is *physically
        present on disk*. It does not inspect the `packageManager`/`engines` signal in
        package.json. So a project that declares e.g. `packageManager: "bun@..."` (or pnpm)
        but has no lockfile yet is claimed by BOTH the dedicated handler and this npm fallback,
        and both restores run. This is pre-existing behavior shared by pnpm/yarn/bun and is
        accepted for now (a real Bun/pnpm project ships a lockfile, so npm correctly skips).
        If this ever needs tightening, also skip here when package.json declares a non-npm
        packageManager/engines signal.
        """
        if Path(document.path).name != NPM_MANIFEST_FILE_NAME:
            return False

        manifest_dir = self.get_manifest_dir(document)
        if not manifest_dir:
            return True

        for lock_file in _ALTERNATIVE_LOCK_FILES:
            if (Path(manifest_dir) / lock_file).is_file():
                logger.debug(
                    'Skipping npm restore: alternative lockfile detected, %s',
                    {'path': document.path, 'lockfile': lock_file},
                )
                return False

        covering_lockfile = _find_workspace_root_lockfile_covering(Path(manifest_dir))
        if covering_lockfile:
            logger.debug(
                'Skipping npm restore: the workspace root lockfile already covers this member, %s',
                {'path': document.path, 'root_lockfile': str(covering_lockfile)},
            )
            return False

        return True

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        return [
            [
                'npm',
                'install',
                '--prefix',
                self.prepare_manifest_file_path_for_command(manifest_file_path),
                '--package-lock-only',
                '--ignore-scripts',
                '--no-audit',
            ]
        ]

    def get_lock_file_name(self) -> str:
        return NPM_LOCK_FILE_NAME

    def get_lock_file_names(self) -> list[str]:
        return [NPM_LOCK_FILE_NAME]

    @staticmethod
    def prepare_manifest_file_path_for_command(manifest_file_path: str) -> str:
        if manifest_file_path.endswith(NPM_MANIFEST_FILE_NAME):
            parent = Path(manifest_file_path).parent
            dir_path = str(parent)
            return dir_path if dir_path and dir_path != '.' else ''
        return manifest_file_path


def _find_workspace_root_lockfile_covering(manifest_dir: Path) -> Optional[Path]:
    """Return the workspace root lockfile that already resolves this member, if there is one.

    npm installs a workspace from the root lockfile and ignores any lockfile inside a member, so a
    member lockfile we generate here would be uploaded and never used.

    A directory only counts as the workspace root when its package.json declares a "workspaces"
    pattern matching the member. A lockfile entry alone is not enough: npm records a file:
    dependency the same way it records a workspace member, and a file: target is not resolved
    through the root lockfile.
    """
    for root_dir in manifest_dir.parents:
        member_path = manifest_dir.relative_to(root_dir).as_posix()
        if not _declares_workspace_member(root_dir / NPM_MANIFEST_FILE_NAME, member_path):
            continue

        for lock_file_name in _WORKSPACE_ROOT_LOCK_FILES:
            lockfile = root_dir / lock_file_name
            if lockfile.is_file() and _lockfile_resolves_member(lockfile, member_path):
                return lockfile

    return None


def _declares_workspace_member(root_manifest: Path, member_path: str) -> bool:
    patterns = _read_workspace_patterns(root_manifest)

    return any(_matches_workspace_pattern(pattern, member_path) for pattern in patterns)


def _read_workspace_patterns(root_manifest: Path) -> list:
    content = _read_json_object(root_manifest)
    if content is None:
        return []

    workspaces = content.get(_MANIFEST_WORKSPACES_SECTION)
    if isinstance(workspaces, dict):
        workspaces = workspaces.get(_MANIFEST_WORKSPACE_PACKAGES_SECTION)

    if not isinstance(workspaces, list):
        return []

    return [pattern for pattern in workspaces if isinstance(pattern, str) and pattern.strip()]


def _matches_workspace_pattern(pattern: str, member_path: str) -> bool:
    normalized = pattern.strip()
    if normalized.startswith('./'):
        normalized = normalized[2:]

    normalized = normalized.rstrip('/')

    return bool(normalized) and re.fullmatch(_workspace_pattern_to_regex(normalized), member_path) is not None


def _workspace_pattern_to_regex(pattern: str) -> str:
    """Translate an npm workspace glob. A single star stops at a path separator, a double star does not."""
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

    return ''.join(parts)


def _lockfile_resolves_member(lockfile: Path, member_path: str) -> bool:
    content = _read_json_object(lockfile)
    if content is None:
        return False

    packages = content.get(_LOCKFILE_PACKAGES_SECTION)
    if not isinstance(packages, dict):
        return False

    return member_path in {name for name in packages if name and _NODE_MODULES_SEPARATOR not in name}


def _read_json_object(path: Path) -> Optional[dict]:
    try:
        content = json.loads(path.read_text(encoding='UTF-8'))
    except (OSError, ValueError) as e:
        logger.debug('Could not read an npm workspace file, %s', {'path': str(path), 'error': e})
        return None

    return content if isinstance(content, dict) else None
