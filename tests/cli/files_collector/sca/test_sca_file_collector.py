from unittest.mock import MagicMock

import click
import pytest
import typer

from cycode.cli.exceptions.custom_exceptions import FileCollectionError
from cycode.cli.files_collector.sca.sca_file_collector import _try_restore_dependencies
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
