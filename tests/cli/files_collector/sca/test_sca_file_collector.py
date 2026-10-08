import json
from pathlib import Path
from unittest.mock import MagicMock

import click
import pytest
import typer

from cycode.cli.exceptions.custom_exceptions import FileCollectionError
from cycode.cli.files_collector.sca.npm import workspace
from cycode.cli.files_collector.sca.sca_file_collector import (
    _add_dependencies_tree_documents,
    _get_doc_ecosystem_related_project_files,
    _get_project_file_ecosystem,
    _try_restore_dependencies,
)
from cycode.cli.models import Document


def _make_ctx(*, stop_on_error: bool = False) -> typer.Context:
    ctx = typer.Context(click.Command('path'), obj={'stop_on_error': stop_on_error, 'monitor': False})
    ctx.obj['path'] = '/some/path'
    return ctx


def _make_handler(*, is_project: bool = True, restore_result: object = None) -> MagicMock:
    handler = MagicMock()
    handler.is_project.return_value = is_project
    handler.restore.return_value = restore_result
    return handler


class TestTryRestoreDependencies:
    def test_returns_none_when_handler_does_not_match(self) -> None:
        ctx = _make_ctx()
        doc = Document('pom.xml', '', is_git_diff_format=False)
        handler = _make_handler(is_project=False)

        result = _try_restore_dependencies(ctx, handler, doc)

        assert result is None
        handler.restore.assert_not_called()

    def test_returns_none_on_restore_failure_without_stop_on_error(self) -> None:
        ctx = _make_ctx(stop_on_error=False)
        doc = Document('pom.xml', '', is_git_diff_format=False)
        handler = _make_handler(is_project=True, restore_result=None)

        result = _try_restore_dependencies(ctx, handler, doc)

        assert result is None

    def test_raises_file_collection_error_on_restore_failure_with_stop_on_error(self) -> None:
        ctx = _make_ctx(stop_on_error=True)
        doc = Document('pom.xml', '', is_git_diff_format=False)
        handler = _make_handler(is_project=True, restore_result=None)
        handler.__class__.__name__ = 'RestoreMavenDependencies'
        type(handler).__name__ = 'RestoreMavenDependencies'

        with pytest.raises(FileCollectionError) as exc_info, ctx:
            _try_restore_dependencies(ctx, handler, doc)

        assert 'pom.xml' in str(exc_info.value)

    def test_returns_document_on_success(self) -> None:
        ctx = _make_ctx()
        doc = Document('pom.xml', '', is_git_diff_format=False)
        restored_doc = Document('pom.xml.lock', 'dep-tree-content', is_git_diff_format=False)
        handler = _make_handler(is_project=True, restore_result=restored_doc)

        with ctx:
            result = _try_restore_dependencies(ctx, handler, doc)

        assert result is restored_doc
        assert result.content == 'dep-tree-content'

    def test_sets_empty_content_when_restore_returns_document_with_none_content(self) -> None:
        ctx = _make_ctx()
        doc = Document('pom.xml', '', is_git_diff_format=False)
        restored_doc = Document('pom.xml.lock', None, is_git_diff_format=False)
        handler = _make_handler(is_project=True, restore_result=restored_doc)

        with ctx:
            result = _try_restore_dependencies(ctx, handler, doc)

        assert result is not None
        assert result.content == ''


class TestNpmWorkspaceCacheLifetime:
    def test_each_scan_starts_with_a_cleared_npm_workspace_cache(self, tmp_path: Path) -> None:
        """The cache memoises root lockfiles by path; a later scan must not inherit a previous scan's view."""
        root_manifest = tmp_path / 'package.json'
        root_manifest.write_text('{"name": "root", "workspaces": ["packages/*"]}')
        lock_file = tmp_path / 'package-lock.json'
        lock_file.write_text(json.dumps({'lockfileVersion': 3, 'packages': {'': {}, 'packages/other': {}}}))

        member_dir = tmp_path / 'packages' / 'app'
        member_dir.mkdir(parents=True)
        manifest = member_dir / 'package.json'
        manifest.write_text('{"name": "app"}')

        assert workspace.find_covering_workspace(str(member_dir)) is None

        lock_file.write_text(json.dumps({'lockfileVersion': 3, 'packages': {'': {}, 'packages/app': {}}}))

        ctx = _make_ctx()
        _add_dependencies_tree_documents(ctx, [Document(str(manifest), manifest.read_text())])

        assert workspace.find_covering_workspace(str(member_dir)) is not None


class TestPnpmWorkspaceRelatedProjectFiles:
    """A diff scan uploads the changed project file plus the project files beside it."""

    def test_pnpm_workspace_file_is_an_npm_project_file(self) -> None:
        assert _get_project_file_ecosystem(Document('repo/pnpm-workspace.yaml', '')) == 'npm'

    def test_changed_pnpm_lockfile_brings_the_workspace_file_along(self, tmp_path: Path) -> None:
        """Without pnpm-workspace.yaml the backend cannot tell which directories the root lockfile resolves."""
        (tmp_path / 'package.json').write_text('{"name": "root"}')
        (tmp_path / 'pnpm-workspace.yaml').write_text('packages:\n  - "packages/*"\n')
        lock_file = tmp_path / 'pnpm-lock.yaml'
        lock_file.write_text("lockfileVersion: '9.0'\n")

        changed = Document(str(lock_file), lock_file.read_text())
        related = _get_doc_ecosystem_related_project_files(changed, [changed], 'npm', None, None)

        assert str(tmp_path / 'pnpm-workspace.yaml') in [document.path for document in related]
