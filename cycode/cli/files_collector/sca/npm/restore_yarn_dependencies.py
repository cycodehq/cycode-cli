import json
from pathlib import Path
from typing import Optional

import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies, build_dep_tree_path
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content
from cycode.logger import get_logger

logger = get_logger('Yarn Restore Dependencies')

YARN_MANIFEST_FILE_NAME = 'package.json'
YARN_LOCK_FILE_NAME = 'yarn.lock'


def _indicates_yarn(package_json_content: Optional[str]) -> bool:
    """Return True if package.json content signals that this project uses Yarn."""
    if not package_json_content:
        return False
    try:
        data = json.loads(package_json_content)
    except (json.JSONDecodeError, ValueError):
        return False

    package_manager = data.get('packageManager', '')
    if isinstance(package_manager, str) and package_manager.startswith('yarn'):
        return True

    engines = data.get('engines', {})
    return isinstance(engines, dict) and 'yarn' in engines


class RestoreYarnDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        if Path(document.path).name != YARN_MANIFEST_FILE_NAME:
            return False

        manifest_dir = self.get_manifest_dir(document)
        if manifest_dir and (Path(manifest_dir) / YARN_LOCK_FILE_NAME).is_file():
            return True

        return _indicates_yarn(document.content)

    def try_restore_dependencies(self, document: Document) -> Optional[Document]:
        manifest_dir = self.get_manifest_dir(document)
        lockfile_path = Path(manifest_dir) / YARN_LOCK_FILE_NAME if manifest_dir else None

        if lockfile_path and lockfile_path.is_file():
            # Lockfile already exists — read it directly without running yarn
            content = get_file_content(str(lockfile_path))
            relative_path = build_dep_tree_path(document.path, YARN_LOCK_FILE_NAME)
            logger.debug('Using existing yarn.lock, %s', {'path': str(lockfile_path)})
            return Document(relative_path, content, self.is_git_diff)

        # Lockfile absent but yarn is indicated in package.json — generate it
        return super().try_restore_dependencies(document)

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        return [['yarn', 'install', '--ignore-scripts']]

    def get_lock_file_name(self) -> str:
        return YARN_LOCK_FILE_NAME

    def get_lock_file_names(self) -> list[str]:
        return [YARN_LOCK_FILE_NAME]
