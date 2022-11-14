from cli.utils.shell_executor import shell
from typing import List
from cli.models import Document
from cli.utils.path_utils import get_file_dir, join_paths

BUILD_GRADLE_FILE_NAME = 'build.gradle'
BUILD_GRADLE_KTS_FILE_NAME = 'build.gradle.kts'
BUILD_GRADLE_DEP_TREE_FILE_NAME = 'gradle-dependencies-generated.txt'
BUILD_GRADLE_DEP_TREE_TIMEOUT = 180


def run_pre_scan_actions(documents_to_scan: List[Document], is_git_diff: bool = False):
    documents_to_add: List[Document] = []
    for document in documents_to_scan:
        if document.path.endswith(BUILD_GRADLE_FILE_NAME) or document.path.endswith(BUILD_GRADLE_KTS_FILE_NAME):
            gradle_dependencies_tree = generate_dependencies_tree(document.path)
            documents_to_add.append(Document(build_dep_tree_path(document.path), gradle_dependencies_tree, is_git_diff))

    documents_to_scan.extend(documents_to_add)


def generate_dependencies_tree(filename: str) -> str:
    command = ['gradle', 'dependencies', '-b', filename, '-q', '--console', 'plain']
    gradle_dependencies = shell(command, BUILD_GRADLE_DEP_TREE_TIMEOUT)

    return gradle_dependencies


def build_dep_tree_path(path):
    return join_paths(get_file_dir(path), BUILD_GRADLE_DEP_TREE_FILE_NAME)
