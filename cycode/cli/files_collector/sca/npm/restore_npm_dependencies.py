from pathlib import Path

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.files_collector.sca.npm.workspace import (
    BUN_LOCK_FILE_NAME,
    DENO_LOCK_FILE_NAME,
    MANIFEST_FILE_NAME,
    NPM_LOCK_FILE_NAME,
    NPM_SHRINKWRAP_FILE_NAME,
    PNPM_LOCK_FILE_NAME,
    YARN_LOCK_FILE_NAME,
    is_covered_workspace_member,
)
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_scan_roots_from_context
from cycode.logger import get_logger

logger = get_logger('NPM Restore Dependencies')

NPM_MANIFEST_FILE_NAME = MANIFEST_FILE_NAME
# These lockfiles indicate another package manager owns the project — NPM should not run
_ALTERNATIVE_LOCK_FILES = (YARN_LOCK_FILE_NAME, PNPM_LOCK_FILE_NAME, DENO_LOCK_FILE_NAME, BUN_LOCK_FILE_NAME)


class RestoreNpmDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        """Match only package.json files that are not managed by Yarn or pnpm.

        Yarn and pnpm projects are handled by their dedicated handlers, which run before
        this one in the handler list. This handler is the npm fallback.

        A manifest is also declined when a lockfile further up already resolves it, whichever
        package manager wrote that lockfile; see the workspace package for how that is decided.

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

        return not is_covered_workspace_member(manifest_dir, document.path, get_scan_roots_from_context(self.ctx))

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
        return [NPM_LOCK_FILE_NAME, NPM_SHRINKWRAP_FILE_NAME]

    def get_restored_lock_file_name(self, restore_file_path: str) -> str:
        name = Path(restore_file_path).name
        return name if name in self.get_lock_file_names() else self.get_lock_file_name()

    @staticmethod
    def prepare_manifest_file_path_for_command(manifest_file_path: str) -> str:
        if manifest_file_path.endswith(NPM_MANIFEST_FILE_NAME):
            parent = Path(manifest_file_path).parent
            dir_path = str(parent)
            return dir_path if dir_path and dir_path != '.' else ''
        return manifest_file_path
