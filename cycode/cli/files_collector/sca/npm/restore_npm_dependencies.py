import os
from typing import Optional

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies, build_dep_tree_path
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content
from cycode.logger import get_logger

logger = get_logger('NPM Restore Dependencies')

NPM_PROJECT_FILE_EXTENSIONS = ['.json']
NPM_LOCK_FILE_NAME = 'package-lock.json'
# Alternative lockfiles that should prevent npm install from running
ALTERNATIVE_LOCK_FILES = ['yarn.lock', 'pnpm-lock.yaml', 'deno.lock']
NPM_LOCK_FILE_NAMES = [NPM_LOCK_FILE_NAME, *ALTERNATIVE_LOCK_FILES]
NPM_MANIFEST_FILE_NAME = 'package.json'


class RestoreNpmDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        return any(document.path.endswith(ext) for ext in NPM_PROJECT_FILE_EXTENSIONS)

    def _resolve_manifest_directory(self, document: Document) -> Optional[str]:
        """Resolve the directory containing the manifest file.

        Uses the same path resolution logic as get_manifest_file_path() to ensure consistency.
        Falls back to absolute_path or document.path if needed.

        Returns:
            Directory path if resolved, None otherwise.
        """
        manifest_file_path = self.get_manifest_file_path(document)
        manifest_dir = os.path.dirname(manifest_file_path) if manifest_file_path else None

        # Fallback: if manifest_dir is empty or root, try using absolute_path or document.path
        if not manifest_dir or manifest_dir == os.sep or manifest_dir == '.':
            base_path = document.absolute_path if document.absolute_path else document.path
            if base_path:
                manifest_dir = os.path.dirname(base_path)

        return manifest_dir

    def _find_existing_lockfile(self, manifest_dir: str) -> tuple[Optional[str], list[str]]:
        """Find the first existing lockfile in the manifest directory.

        Args:
            manifest_dir: Directory to search for lockfiles.

        Returns:
            Tuple of (lockfile_path if found, list of checked lockfiles with status).
        """
        lock_file_paths = [os.path.join(manifest_dir, lock_file_name) for lock_file_name in NPM_LOCK_FILE_NAMES]

        existing_lock_file = None
        checked_lockfiles = []
        for lock_file_path in lock_file_paths:
            lock_file_name = os.path.basename(lock_file_path)
            exists = os.path.isfile(lock_file_path)
            checked_lockfiles.append(f'{lock_file_name}: {"exists" if exists else "not found"}')
            if exists:
                existing_lock_file = lock_file_path
                break

        return existing_lock_file, checked_lockfiles

    def _create_document_from_lockfile(self, document: Document, lockfile_path: str) -> Optional[Document]:
        """Create a Document from an existing lockfile.

        Args:
            document: Original document (package.json).
            lockfile_path: Path to the existing lockfile.

        Returns:
            Document with lockfile content if successful, None otherwise.
        """
        lock_file_name = os.path.basename(lockfile_path)
        logger.info(
            'Skipping npm install: using existing lockfile, %s',
            {'path': document.path, 'lockfile': lock_file_name, 'lockfile_path': lockfile_path},
        )

        relative_restore_file_path = build_dep_tree_path(document.path, lock_file_name)
        restore_file_content = get_file_content(lockfile_path)

        if restore_file_content is not None:
            logger.debug(
                'Successfully loaded lockfile content, %s',
                {'path': document.path, 'lockfile': lock_file_name, 'content_size': len(restore_file_content)},
            )
            return Document(relative_restore_file_path, restore_file_content, self.is_git_diff)

        logger.warning(
            'Lockfile exists but could not read content, %s',
            {'path': document.path, 'lockfile': lock_file_name, 'lockfile_path': lockfile_path},
        )
        return None

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        """Override to prevent npm install when any lockfile exists.

        The base class uses document.absolute_path which might be None or incorrect.
        We need to use the same path resolution logic as get_manifest_file_path()
        to ensure we check for lockfiles in the correct location.

        If any lockfile exists (package-lock.json, pnpm-lock.yaml, yarn.lock, deno.lock),
        we use it directly without running npm install to avoid generating invalid lockfiles.
        """
        # Check if this is a project file first (same as base class caller does)
        if not self.is_project(document):
            logger.debug('Skipping restore: document is not recognized as npm project, %s', {'path': document.path})
            return None

        # Resolve the manifest directory
        manifest_dir = self._resolve_manifest_directory(document)
        if not manifest_dir:
            logger.debug(
                'Cannot determine manifest directory, proceeding with base class restore flow, %s',
                {'path': document.path},
            )
            return super().try_restore_dependencies(document)

        # Check for existing lockfiles
        logger.debug(
            'Checking for existing lockfiles in directory, %s', {'directory': manifest_dir, 'path': document.path}
        )
        existing_lock_file, checked_lockfiles = self._find_existing_lockfile(manifest_dir)

        logger.debug(
            'Lockfile check results, %s',
            {'path': document.path, 'checked_lockfiles': ', '.join(checked_lockfiles)},
        )

        # If any lockfile exists, use it directly without running npm install
        if existing_lock_file:
            return self._create_document_from_lockfile(document, existing_lock_file)

        # No lockfile exists, proceed with the normal restore flow which will run npm install
        logger.info(
            'No existing lockfile found, proceeding with npm install to generate package-lock.json, %s',
            {'path': document.path, 'directory': manifest_dir, 'checked_lockfiles': ', '.join(checked_lockfiles)},
        )
        return super().try_restore_dependencies(document)

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

    def get_restored_lock_file_name(self, restore_file_path: str) -> str:
        return os.path.basename(restore_file_path)

    def get_lock_file_name(self) -> str:
        return NPM_LOCK_FILE_NAME

    def get_lock_file_names(self) -> list[str]:
        return NPM_LOCK_FILE_NAMES

    @staticmethod
    def prepare_manifest_file_path_for_command(manifest_file_path: str) -> str:
        # Remove package.json from the path
        if manifest_file_path.endswith(NPM_MANIFEST_FILE_NAME):
            # Use os.path.dirname to handle both Unix (/) and Windows (\) separators
            # This is cross-platform and handles edge cases correctly
            dir_path = os.path.dirname(manifest_file_path)
            # If dir_path is empty or just '.', return an empty string (package.json in current dir)
            return dir_path if dir_path and dir_path != '.' else ''
        return manifest_file_path
