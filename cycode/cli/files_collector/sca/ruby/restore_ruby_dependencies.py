from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document

RUBY_PROJECT_FILE_EXTENSIONS = ['Gemfile']
RUBY_LOCK_FILE_NAME = 'Gemfile.lock'


class RestoreRubyDependencies(BaseRestoreDependencies):
    def is_project(self, document: Document) -> bool:
        return any(document.path.endswith(ext) for ext in RUBY_PROJECT_FILE_EXTENSIONS)

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        return [['bundle', '--quiet']]

    def get_lock_file_name(self) -> str:
        return RUBY_LOCK_FILE_NAME
