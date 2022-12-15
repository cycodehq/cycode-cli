import click
from typing import List, Optional
from git import Repo, GitCommandError
from cli.utils.shell_executor import shell
from cli.models import Document
from cli.utils.path_utils import get_file_dir, join_paths
from cyclient import logger
from cli.consts import *

BUILD_GRADLE_FILE_NAME = 'build.gradle'
BUILD_GRADLE_KTS_FILE_NAME = 'build.gradle.kts'
BUILD_GRADLE_DEP_TREE_FILE_NAME = 'gradle-dependencies-generated.txt'
BUILD_GRADLE_DEP_TREE_TIMEOUT = 180


def perform_pre_commit_range_scan_actions(path: str, from_commit_documents: List[Document],
                                          from_commit_rev: str, to_commit_documents: List[Document],
                                          to_commit_rev: str) -> None:
    repo = Repo(path)
    add_ecosystem_related_files_if_exists(from_commit_documents, repo, from_commit_rev)
    add_ecosystem_related_files_if_exists(to_commit_documents, repo, to_commit_rev)


def add_ecosystem_related_files_if_exists(documents: List[Document], repo: Repo, commit_rev: str):
    documents_to_add: List[Document] = []
    for doc in documents:
        ecosystem = get_project_file_ecosystem(doc)
        if ecosystem is None:
            logger.debug("failed to resolve project file ecosystem: %s", doc.path)
            continue
        documents_to_add = get_ecosystem_project_files_if_exists(documents, commit_rev, doc, ecosystem, repo)

    documents.extend(documents_to_add)


def get_ecosystem_project_files_if_exists(documents, commit_rev, doc, ecosystem, repo):
    documents_to_add: List[Document] = []
    for ecosystem_project_file in PROJECT_FILES_BY_ECOSYSTEM_MAP.get(ecosystem):
        file_to_search = join_paths(get_file_dir(doc.path), ecosystem_project_file)
        if not is_project_file_exists_in_documents(documents, file_to_search):
            try:
                file_content = repo.git.show(f'{commit_rev}:{file_to_search}')
            except GitCommandError:
                continue
            documents_to_add.append(Document(file_to_search, file_content))
    return documents_to_add


def is_project_file_exists_in_documents(documents: List[Document], file: str):
    return any(doc for doc in documents if file == doc.path)


def get_project_file_ecosystem(document: Document):
    for ecosystem, project_files in PROJECT_FILES_BY_ECOSYSTEM_MAP.items():
        for project_file in project_files:
            if document.path.endswith(project_file):
                return ecosystem
    return None


def add_dependencies_tree_document(context: click.Context, documents_to_scan: List[Document],
                                   is_git_diff: bool = False) -> None:
    is_monitor_action = context.obj.get('monitor')
    project_path = context.params.get('path')
    documents_to_add: List[Document] = []
    for document in documents_to_scan:
        if is_gradle_project(document):
            gradle_dependencies_tree = try_generate_dependencies_tree(
                get_manifest_file_path(document, is_monitor_action, project_path))
            if gradle_dependencies_tree is None:
                logger.warning('Error occurred while trying to generate gradle dependencies tree. %s',
                               {'filename': document.path})
                documents_to_add.append(
                    Document(build_dep_tree_path(document.path, BUILD_GRADLE_DEP_TREE_FILE_NAME), '', is_git_diff))
            else:
                documents_to_add.append(
                    Document(build_dep_tree_path(document.path, BUILD_GRADLE_DEP_TREE_FILE_NAME),
                             gradle_dependencies_tree, is_git_diff))

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
