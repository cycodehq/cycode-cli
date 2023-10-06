import os
from typing import TYPE_CHECKING, Dict, List, Optional

import click
from git import GitCommandError, Repo

from cycode.cli import consts
from cycode.cli.files_collector.sca.maven.restore_gradle_dependencies import RestoreGradleDependencies
from cycode.cli.files_collector.sca.maven.restore_maven_dependencies import RestoreMavenDependencies
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import get_file_content, get_file_dir, join_paths
from cycode.cyclient import logger

if TYPE_CHECKING:
    from cycode.cli.files_collector.sca.maven.base_restore_maven_dependencies import BaseRestoreMavenDependencies

BUILD_GRADLE_FILE_NAME = 'build.gradle'
BUILD_GRADLE_KTS_FILE_NAME = 'build.gradle.kts'
BUILD_GRADLE_DEP_TREE_FILE_NAME = 'gradle-dependencies-generated.txt'
BUILD_GRADLE_DEP_TREE_TIMEOUT = 180


def perform_pre_commit_range_scan_actions(
    path: str,
    from_commit_documents: List[Document],
    from_commit_rev: str,
    to_commit_documents: List[Document],
    to_commit_rev: str,
) -> None:
    repo = Repo(path)
    add_ecosystem_related_files_if_exists(from_commit_documents, repo, from_commit_rev)
    add_ecosystem_related_files_if_exists(to_commit_documents, repo, to_commit_rev)


def perform_pre_hook_range_scan_actions(
    git_head_documents: List[Document], pre_committed_documents: List[Document]
) -> None:
    repo = Repo(os.getcwd())
    add_ecosystem_related_files_if_exists(git_head_documents, repo, consts.GIT_HEAD_COMMIT_REV)
    add_ecosystem_related_files_if_exists(pre_committed_documents)


def add_ecosystem_related_files_if_exists(
    documents: List[Document], repo: Optional[Repo] = None, commit_rev: Optional[str] = None
) -> None:
    documents_to_add: List[Document] = []
    for doc in documents:
        ecosystem = get_project_file_ecosystem(doc)
        if ecosystem is None:
            logger.debug('failed to resolve project file ecosystem: %s', doc.path)
            continue

        documents_to_add.extend(get_doc_ecosystem_related_project_files(doc, documents, ecosystem, commit_rev, repo))

    documents.extend(documents_to_add)


def get_doc_ecosystem_related_project_files(
    doc: Document, documents: List[Document], ecosystem: str, commit_rev: Optional[str], repo: Optional[Repo]
) -> List[Document]:
    documents_to_add: List[Document] = []
    for ecosystem_project_file in consts.PROJECT_FILES_BY_ECOSYSTEM_MAP.get(ecosystem):
        file_to_search = join_paths(get_file_dir(doc.path), ecosystem_project_file)
        if not is_project_file_exists_in_documents(documents, file_to_search):
            if repo:
                file_content = get_file_content_from_commit(repo, commit_rev, file_to_search)
            else:
                file_content = get_file_content(file_to_search)

            if file_content is not None:
                documents_to_add.append(Document(file_to_search, file_content))

    return documents_to_add


def is_project_file_exists_in_documents(documents: List[Document], file: str) -> bool:
    return any(doc for doc in documents if file == doc.path)


def get_project_file_ecosystem(document: Document) -> Optional[str]:
    for ecosystem, project_files in consts.PROJECT_FILES_BY_ECOSYSTEM_MAP.items():
        for project_file in project_files:
            if document.path.endswith(project_file):
                return ecosystem
    return None


def try_restore_dependencies(
    context: click.Context,
    documents_to_add: Dict[str, Document],
    restore_dependencies: 'BaseRestoreMavenDependencies',
    document: Document,
) -> None:
    if restore_dependencies.is_project(document):
        restore_dependencies_document = restore_dependencies.restore(document)
        if restore_dependencies_document is None:
            logger.warning('Error occurred while trying to generate dependencies tree. %s', {'filename': document.path})
            return

        if restore_dependencies_document.content is None:
            logger.warning('Error occurred while trying to generate dependencies tree. %s', {'filename': document.path})
            restore_dependencies_document.content = ''
        else:
            is_monitor_action = context.obj.get('monitor')
            project_path = context.params.get('path')
            manifest_file_path = get_manifest_file_path(document, is_monitor_action, project_path)
            logger.debug(f'Succeeded to generate dependencies tree on path: {manifest_file_path}')

        if restore_dependencies_document.path in documents_to_add:
            logger.debug(f'Duplicate document on restore for path: {restore_dependencies_document.path}')
        else:
            documents_to_add[restore_dependencies_document.path] = restore_dependencies_document


def add_dependencies_tree_document(
    context: click.Context, documents_to_scan: List[Document], is_git_diff: bool = False
) -> None:
    documents_to_add: Dict[str, Document] = {}
    restore_dependencies_list = restore_handlers(context, is_git_diff)

    for restore_dependencies in restore_dependencies_list:
        for document in documents_to_scan:
            try_restore_dependencies(context, documents_to_add, restore_dependencies, document)

    documents_to_scan.extend(list(documents_to_add.values()))


def restore_handlers(context: click.Context, is_git_diff: bool) -> List[RestoreGradleDependencies]:
    return [
        RestoreGradleDependencies(context, is_git_diff, BUILD_GRADLE_DEP_TREE_TIMEOUT),
        RestoreMavenDependencies(context, is_git_diff, BUILD_GRADLE_DEP_TREE_TIMEOUT),
    ]


def get_manifest_file_path(document: Document, is_monitor_action: bool, project_path: str) -> str:
    return join_paths(project_path, document.path) if is_monitor_action else document.path


def get_file_content_from_commit(repo: Repo, commit: str, file_path: str) -> Optional[str]:
    try:
        return repo.git.show(f'{commit}:{file_path}')
    except GitCommandError:
        return None


def perform_pre_scan_documents_actions(
    context: click.Context, scan_type: str, documents_to_scan: List[Document], is_git_diff: bool = False
) -> None:
    if scan_type == consts.SCA_SCAN_TYPE and not context.obj.get(consts.SCA_SKIP_RESTORE_DEPENDENCIES_FLAG):
        logger.debug('Perform pre scan document add_dependencies_tree_document action')
        add_dependencies_tree_document(context, documents_to_scan, is_git_diff)
