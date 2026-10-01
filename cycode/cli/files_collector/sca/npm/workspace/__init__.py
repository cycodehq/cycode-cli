"""Deciding whether a lockfile above a manifest already resolves that manifest's dependencies.

The lockfile is the authority wherever it can name its members; the manifest's workspaces globs
are a fallback for the formats that cannot. See resolvers.py for the per-format readers.
"""

from cycode.cli.files_collector.sca.npm.workspace import coverage as _coverage
from cycode.cli.files_collector.sca.npm.workspace import globs as _globs
from cycode.cli.files_collector.sca.npm.workspace import resolvers as _resolvers
from cycode.cli.files_collector.sca.npm.workspace.coverage import (
    WorkspaceCoverage,
    find_covering_workspace,
    is_covered_workspace_member,
)
from cycode.cli.files_collector.sca.npm.workspace.names import (
    BUN_BINARY_LOCK_FILE_NAME,
    BUN_LOCK_FILE_NAME,
    BUN_PACKAGE_MANAGER,
    DENO_LOCK_FILE_NAME,
    DENO_PACKAGE_MANAGER,
    MANIFEST_FILE_NAME,
    NPM_LOCK_FILE_NAME,
    NPM_PACKAGE_MANAGER,
    NPM_SHRINKWRAP_FILE_NAME,
    PNPM_LOCK_FILE_NAME,
    PNPM_PACKAGE_MANAGER,
    YARN_LOCK_FILE_NAME,
    YARN_PACKAGE_MANAGER,
)
from cycode.cli.files_collector.sca.npm.workspace.resolvers import MEMBER_RESOLVERS


def clear_cache() -> None:
    """Drop every memo, so one scan never inherits another scan's view of the filesystem."""
    _resolvers.clear_cache()
    _globs.clear_cache()
    _coverage.clear_cache()


__all__ = [
    'BUN_BINARY_LOCK_FILE_NAME',
    'BUN_LOCK_FILE_NAME',
    'BUN_PACKAGE_MANAGER',
    'DENO_LOCK_FILE_NAME',
    'DENO_PACKAGE_MANAGER',
    'MANIFEST_FILE_NAME',
    'MEMBER_RESOLVERS',
    'NPM_LOCK_FILE_NAME',
    'NPM_PACKAGE_MANAGER',
    'NPM_SHRINKWRAP_FILE_NAME',
    'PNPM_LOCK_FILE_NAME',
    'PNPM_PACKAGE_MANAGER',
    'YARN_LOCK_FILE_NAME',
    'YARN_PACKAGE_MANAGER',
    'WorkspaceCoverage',
    'clear_cache',
    'find_covering_workspace',
    'is_covered_workspace_member',
]
