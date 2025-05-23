from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document

SBT_PROJECT_FILE_EXTENSIONS = ['sbt']
SBT_LOCK_FILE_NAME = 'build.sbt.lock'


class RestoreSbtDependencies(BaseRestoreDependencies):
    def is_project(self, document: Document) -> bool:
        return any(document.path.endswith(ext) for ext in SBT_PROJECT_FILE_EXTENSIONS)

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        return [['sbt', 'dependencyLockWrite', '--verbose']]

    def get_lock_file_name(self) -> str:
        return SBT_LOCK_FILE_NAME
