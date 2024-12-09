import os
from typing import List, Optional

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document

SBT_PROJECT_FILE_EXTENSIONS = ['sbt']
SBT_LOCK_FILE_NAME = 'build.sbt.lock'


class RestoreSbtDependencies(BaseRestoreDependencies):
    def is_project(self, document: Document) -> bool:
        return any(document.path.endswith(ext) for ext in SBT_PROJECT_FILE_EXTENSIONS)

    def get_commands(self, manifest_file_path: str) -> List[List[str]]:
        return [['sbt', 'dependencyLockWrite', '--verbose']]

    def get_lock_file_name(self) -> str:
        return SBT_LOCK_FILE_NAME

    def verify_restore_file_already_exist(self, restore_file_path: str) -> bool:
        return os.path.isfile(restore_file_path)

    def get_working_directory(self, document: Document) -> Optional[str]:
        return os.path.dirname(document.absolute_path)