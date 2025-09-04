import os
from typing import TYPE_CHECKING, Optional

import typer

from cycode.cli import consts
from cycode.cli.files_collector.repository_documents import get_file_content_from_commit_path
from cycode.cli.files_collector.sca.base_restore_dependencies import BaseRestoreDependencies
from cycode.cli.files_collector.sca.go.restore_go_dependencies import RestoreGoDependencies
from cycode.cli.files_collector.sca.maven.restore_gradle_dependencies import RestoreGradleDependencies
from cycode.cli.files_collector.sca.maven.restore_maven_dependencies import RestoreMavenDependencies
from cycode.cli.files_collector.sca.npm.restore_npm_dependencies import RestoreNpmDependencies
from cycode.cli.files_collector.sca.nuget.restore_nuget_dependencies import RestoreNugetDependencies
from cycode.cli.files_collector.sca.ruby.restore_ruby_dependencies import RestoreRubyDependencies
from cycode.cli.files_collector.sca.sbt.restore_sbt_dependencies import RestoreSbtDependencies
from cycode.cli.models import Document
from cycode.cli.utils.git_proxy import git_proxy
from cycode.cli.utils.path_utils import get_file_content, get_file_dir, get_path_from_context, join_paths
from cycode.logger import get_logger

if TYPE_CHECKING:
    from git import Repo

BUILD_DEP_TREE_TIMEOUT = 180


logger = get_logger('SCA File Collector')


def _add_ecosystem_related_files_if_exists(
    documents: list[Document], repo: Optional['Repo'] = None, commit_rev: Optional[str] = None
) -> None:
    documents_to_add: list[Document] = []
    for doc in documents:
        ecosystem = _get_project_file_ecosystem(doc)
        if ecosystem is None:
            logger.debug('Failed to resolve project file ecosystem: %s', doc.path)
            continue

        documents_to_add.extend(_get_doc_ecosystem_related_project_files(doc, documents, ecosystem, commit_rev, repo))

    documents.extend(documents_to_add)


def perform_sca_pre_commit_range_scan_actions(
    path: str,
    from_commit_documents: list[Document],
    from_commit_rev: str,
    to_commit_documents: list[Document],
    to_commit_rev: str,
) -> None:
    repo = git_proxy.get_repo(path)
    _add_ecosystem_related_files_if_exists(from_commit_documents, repo, from_commit_rev)
    _add_ecosystem_related_files_if_exists(to_commit_documents, repo, to_commit_rev)


def perform_sca_pre_hook_range_scan_actions(
    repo_path: str, git_head_documents: list[Document], pre_committed_documents: list[Document]
) -> None:
    repo = git_proxy.get_repo(repo_path)
    _add_ecosystem_related_files_if_exists(git_head_documents, repo, consts.GIT_HEAD_COMMIT_REV)
    _add_ecosystem_related_files_if_exists(pre_committed_documents)


def _get_doc_ecosystem_related_project_files(
    doc: Document, documents: list[Document], ecosystem: str, commit_rev: Optional[str], repo: Optional['Repo']
) -> list[Document]:
    documents_to_add: list[Document] = []
    for ecosystem_project_file in consts.PROJECT_FILES_BY_ECOSYSTEM_MAP.get(ecosystem):
        file_to_search = join_paths(get_file_dir(doc.path), ecosystem_project_file)
        if not _is_project_file_exists_in_documents(documents, file_to_search):
            if repo:
                file_content = get_file_content_from_commit_path(repo, commit_rev, file_to_search)
            else:
                file_content = get_file_content(file_to_search)

            if file_content is not None:
                documents_to_add.append(Document(file_to_search, file_content))

    return documents_to_add


def _is_project_file_exists_in_documents(documents: list[Document], file: str) -> bool:
    return any(doc for doc in documents if file == doc.path)


def _get_project_file_ecosystem(document: Document) -> Optional[str]:
    for ecosystem, project_files in consts.PROJECT_FILES_BY_ECOSYSTEM_MAP.items():
        for project_file in project_files:
            if document.path.endswith(project_file):
                return ecosystem
    return None


def _get_manifest_file_path(document: Document, is_monitor_action: bool, project_path: str) -> str:
    return join_paths(project_path, document.path) if is_monitor_action else document.path


def _try_restore_dependencies(
    ctx: typer.Context,
    restore_dependencies: 'BaseRestoreDependencies',
    document: Document,
) -> Optional[Document]:
    if not restore_dependencies.is_project(document):
        return None

    restore_dependencies_document = restore_dependencies.restore(document)
    if restore_dependencies_document is None:
        logger.warning('Error occurred while trying to generate dependencies tree, %s', {'filename': document.path})
        return None

    if restore_dependencies_document.content is None:
        logger.warning('Error occurred while trying to generate dependencies tree, %s', {'filename': document.path})
        restore_dependencies_document.content = ''
    else:
        is_monitor_action = ctx.obj.get('monitor', False)
        project_path = get_path_from_context(ctx)

        manifest_file_path = _get_manifest_file_path(document, is_monitor_action, project_path)
        logger.debug('Succeeded to generate dependencies tree on path: %s', manifest_file_path)

    return restore_dependencies_document


def _get_restore_handlers(ctx: typer.Context, is_git_diff: bool) -> list[BaseRestoreDependencies]:
    build_dep_tree_timeout = int(os.getenv('CYCODE_BUILD_DEP_TREE_TIMEOUT_SECONDS', BUILD_DEP_TREE_TIMEOUT))
    return [
        RestoreGradleDependencies(ctx, is_git_diff, build_dep_tree_timeout),
        RestoreMavenDependencies(ctx, is_git_diff, build_dep_tree_timeout),
        RestoreSbtDependencies(ctx, is_git_diff, build_dep_tree_timeout),
        RestoreGoDependencies(ctx, is_git_diff, build_dep_tree_timeout),
        RestoreNugetDependencies(ctx, is_git_diff, build_dep_tree_timeout),
        RestoreNpmDependencies(ctx, is_git_diff, build_dep_tree_timeout),
        RestoreRubyDependencies(ctx, is_git_diff, build_dep_tree_timeout),
    ]


def _add_dependencies_tree_documents(
    ctx: typer.Context, documents_to_scan: list[Document], is_git_diff: bool = False
) -> None:
    logger.debug(
        'Adding dependencies tree documents, %s',
        {'documents_count': len(documents_to_scan), 'is_git_diff': is_git_diff},
    )

    documents_to_add: dict[str, Document] = {document.path: document for document in documents_to_scan}
    restore_dependencies_list = _get_restore_handlers(ctx, is_git_diff)

    for restore_dependencies in restore_dependencies_list:
        for document in documents_to_scan:
            restore_dependencies_document = _try_restore_dependencies(ctx, restore_dependencies, document)
            if restore_dependencies_document is None:
                continue

            if restore_dependencies_document.path in documents_to_add:
                logger.debug('Duplicate document on restore for path: %s', restore_dependencies_document.path)
            else:
                logger.debug('Adding dependencies tree document, %s', restore_dependencies_document.path)
                documents_to_add[restore_dependencies_document.path] = restore_dependencies_document

    logger.debug('Finished adding dependencies tree documents, %s', {'documents_count': len(documents_to_add)})

    # mutate original list using slice assignment
    documents_to_scan[:] = list(documents_to_add.values())


def add_sca_dependencies_tree_documents_if_needed(
    ctx: typer.Context, scan_type: str, documents_to_scan: list[Document], is_git_diff: bool = False
) -> None:
    no_restore = ctx.obj.get('no_restore', False)
    if scan_type == consts.SCA_SCAN_TYPE and not no_restore:
        _add_dependencies_tree_documents(ctx, documents_to_scan, is_git_diff)
