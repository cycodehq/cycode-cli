from cli.utils.shell_executor import shell
from typing import List
from cli.models import Document

BUILD_GRADLE_FILE_NAME = 'build.gradle'
BUILD_GRADLE_DEP_TREE_FILE_NAME = 'gradle-dependencies-generated.txt'


def run_pre_scan_actions(documents_to_scan: List[Document], is_git_diff: bool = False):
    documents_to_add: List[Document] = []
    for document in documents_to_scan:
        if document.path.endswith(BUILD_GRADLE_FILE_NAME):
            gradle_dependencies_tree = _generate_dependencies_tree(document.path)
            documents_to_add.append(Document(BUILD_GRADLE_DEP_TREE_FILE_NAME, gradle_dependencies_tree, is_git_diff))

    documents_to_scan.extend(documents_to_add)


def _generate_dependencies_tree(filename: str) -> str:
    command = ['gradle', 'dependencies', '-b', filename, '-q', '--console', 'plain']
    gradle_dependencies = shell(command, 180)

    return gradle_dependencies
