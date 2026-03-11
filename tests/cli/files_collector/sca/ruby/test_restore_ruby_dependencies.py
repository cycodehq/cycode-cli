from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.files_collector.sca.ruby.restore_ruby_dependencies import (
    RUBY_LOCK_FILE_NAME,
    RestoreRubyDependencies,
)
from cycode.cli.models import Document

_BASE_MODULE = 'cycode.cli.files_collector.sca.base_restore_dependencies'


@pytest.fixture
def mock_ctx(tmp_path: Path) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {'monitor': False}
    ctx.params = {'path': str(tmp_path)}
    return ctx


@pytest.fixture
def restore_ruby(mock_ctx: typer.Context) -> RestoreRubyDependencies:
    return RestoreRubyDependencies(mock_ctx, is_git_diff=False, command_timeout=30)


class TestIsProject:
    def test_gemfile_matches(self, restore_ruby: RestoreRubyDependencies) -> None:
        doc = Document('Gemfile', "source 'https://rubygems.org'\n")
        assert restore_ruby.is_project(doc) is True

    def test_gemfile_in_subdir_matches(self, restore_ruby: RestoreRubyDependencies) -> None:
        doc = Document('myapp/Gemfile', "source 'https://rubygems.org'\n")
        assert restore_ruby.is_project(doc) is True

    def test_gemfile_lock_does_not_match(self, restore_ruby: RestoreRubyDependencies) -> None:
        doc = Document('Gemfile.lock', 'GEM\n  remote: https://rubygems.org/\n')
        assert restore_ruby.is_project(doc) is False

    def test_other_file_does_not_match(self, restore_ruby: RestoreRubyDependencies) -> None:
        doc = Document('Rakefile', '')
        assert restore_ruby.is_project(doc) is False


class TestCleanup:
    def test_generated_lockfile_is_deleted_after_restore(
        self, restore_ruby: RestoreRubyDependencies, tmp_path: Path
    ) -> None:
        (tmp_path / 'Gemfile').write_text("source 'https://rubygems.org'\n")
        doc = Document(
            str(tmp_path / 'Gemfile'),
            "source 'https://rubygems.org'\n",
            absolute_path=str(tmp_path / 'Gemfile'),
        )
        lock_path = tmp_path / RUBY_LOCK_FILE_NAME

        def side_effect(
            commands: list,
            timeout: int,
            output_file_path: Optional[str] = None,
            working_directory: Optional[str] = None,
        ) -> str:
            lock_path.write_text('GEM\n  remote: https://rubygems.org/\n  specs:\n')
            return 'output'

        with patch(f'{_BASE_MODULE}.execute_commands', side_effect=side_effect):
            result = restore_ruby.try_restore_dependencies(doc)

        assert result is not None
        assert not lock_path.exists(), f'{RUBY_LOCK_FILE_NAME} must be deleted after restore'

    def test_preexisting_lockfile_is_not_deleted(self, restore_ruby: RestoreRubyDependencies, tmp_path: Path) -> None:
        lock_content = 'GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n'
        (tmp_path / 'Gemfile').write_text("source 'https://rubygems.org'\ngem 'rake'\n")
        lock_path = tmp_path / RUBY_LOCK_FILE_NAME
        lock_path.write_text(lock_content)
        doc = Document(
            str(tmp_path / 'Gemfile'),
            "source 'https://rubygems.org'\ngem 'rake'\n",
            absolute_path=str(tmp_path / 'Gemfile'),
        )

        result = restore_ruby.try_restore_dependencies(doc)

        assert result is not None
        assert lock_path.exists(), f'Pre-existing {RUBY_LOCK_FILE_NAME} must not be deleted'
