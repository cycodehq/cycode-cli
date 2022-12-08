import click
from typing import List, Optional
from cli.utils.shell_executor import shell
from cli.models import Document
from cli.utils.path_utils import get_file_dir, join_paths
from cyclient import logger

BUILD_GRADLE_FILE_NAME = 'build.gradle'
BUILD_GRADLE_KTS_FILE_NAME = 'build.gradle.kts'
BUILD_GRADLE_DEP_TREE_FILE_NAME = 'gradle-dependencies-generated.txt'
BUILD_GRADLE_DEP_TREE_COMMIT_RANGE_FROM_FILE_NAME = 'from-gradle-dependencies-generated.txt'
BUILD_GRADLE_DEP_TREE_COMMIT_RANGE_TO_FILE_NAME = 'to-gradle-dependencies-generated.txt'
BUILD_GRADLE_DEP_TREE_TIMEOUT = 180


def perform_pre_commit_range_scan_actions(path: str, documents_to_scan: List[Document], from_commit: str,
                                          to_commit: str) -> None:
    repo = Repo(path)
    if repo.is_dirty(untracked_files=True):
        raise click.ClickException("Couldn't run dependencies over commit range, repo is dirty.")

    current_head = get_current_git_head(repo)
    try:
        # run restore over first commit on range
        repo.git.checkout(from_commit)
        add_dependencies_tree_document(documents_to_scan, BUILD_GRADLE_DEP_TREE_COMMIT_RANGE_FROM_FILE_NAME)
        # run restore over last commit on range
        repo.git.checkout(to_commit)
        add_dependencies_tree_document(documents_to_scan, BUILD_GRADLE_DEP_TREE_COMMIT_RANGE_TO_FILE_NAME)
        # revert to initial state
    finally:
        repo.git.checkout(current_head)


def add_dependencies_tree_document(context: click.Context, documents_to_scan: List[Document], is_git_diff: bool = False) -> None:
    documents_to_add: List[Document] = []
    for document in documents_to_scan:
        if is_gradle_project(document):
            gradle_dependencies_tree = try_generate_dependencies_tree(get_manifest_file_path(document, is_monitor_action, project_path))
            if gradle_dependencies_tree is None:
                logger.warning('Error occurred while trying to generate gradle dependencies tree. %s',
                               {'filename': document.path})
                documents_to_add.append(
                    Document(build_dep_tree_path(document.path, generated_file_name), '', False))
            else:
                documents_to_add.append(
                    Document(build_dep_tree_path(document.path, generated_file_name), gradle_dependencies_tree, False))

    documents_to_scan.extend(documents_to_add)


def get_manifest_file_path(document, is_monitor_action, project_path):
    return join_paths(project_path, document.path) if is_monitor_action else document.path


def try_generate_dependencies_tree(filename: str) -> Optional[str]:
    command = ['gradle', 'dependencies', '-b', filename, '-q', '--console', 'plain']
    try:
        gradle_dependencies = shell(command, BUILD_GRADLE_DEP_TREE_TIMEOUT)
    except Exception as e:
        logger.debug('Failed to run gradle dependencies tree shell comment. %s',
                     {'filename': filename, 'exception': str(e)})
        return None

    return gradle_dependencies


def build_dep_tree_path(path: str, generated_file_name: str) -> str:
    return join_paths(get_file_dir(path), generated_file_name)


def is_gradle_project(document: Document) -> bool:
    return document.path.endswith(BUILD_GRADLE_FILE_NAME) or document.path.endswith(BUILD_GRADLE_KTS_FILE_NAME)


def get_current_git_head(repo: Repo) -> str:
    try:
        current_head = repo.active_branch
    except (Exception,):
        current_head = repo.head.object.hexsha
    return current_head
