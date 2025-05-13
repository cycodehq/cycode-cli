import typer

from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.models import Document

NUGET_PROJECT_FILE_EXTENSIONS = ['.csproj', '.vbproj']
NUGET_LOCK_FILE_NAME = 'packages.lock.json'


class RestoreNugetDependencies(BaseRestoreDependencies):
    def __init__(self, ctx: typer.Context, is_git_diff: bool, command_timeout: int) -> None:
        super().__init__(ctx, is_git_diff, command_timeout)

    def is_project(self, document: Document) -> bool:
        return any(document.path.endswith(ext) for ext in NUGET_PROJECT_FILE_EXTENSIONS)

    def get_commands(self, manifest_file_path: str) -> list[list[str]]:
        return [['dotnet', 'restore', manifest_file_path, '--use-lock-file', '--verbosity', 'quiet']]

    def get_lock_file_name(self) -> str:
        return NUGET_LOCK_FILE_NAME
