from pathlib import Path

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document
from cycode.logger import get_logger

logger = get_logger('NPM Restore Dependencies')

NPM_MANIFEST_FILE_NAME = 'package.json'
NPM_LOCK_FILE_NAME = 'package-lock.json'
# These lockfiles indicate another package manager owns the project — NPM should not run
_ALTERNATIVE_LOCK_FILES = ('yarn.lock', 'pnpm-lock.yaml', 'deno.lock')


class RestoreNpmDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        """Match only package.json files that are not managed by Yarn or pnpm.

        Yarn and pnpm projects are handled by their dedicated handlers, which run before
        this one in the handler list. This handler is the npm fallback.
        """
        if Path(document.path).name != NPM_MANIFEST_FILE_NAME:
            return False

        manifest_dir = self.get_manifest_dir(document)
        if manifest_dir:
            for lock_file in _ALTERNATIVE_LOCK_FILES:
                if (Path(manifest_dir) / lock_file).is_file():
                    logger.debug(
                        'Skipping npm restore: alternative lockfile detected, %s',
                        {'path': document.path, 'lockfile': lock_file},
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
