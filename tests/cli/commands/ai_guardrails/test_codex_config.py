"""Tests for Codex config.toml feature flag management."""

import sys
from pathlib import Path

from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.codex_config import (
    enable_codex_hooks_feature,
    get_codex_config_path,
)

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib


def _read_toml(path: Path) -> dict:
    with path.open('rb') as f:
        return tomllib.load(f)


def test_get_codex_config_path_user_scope() -> None:
    assert get_codex_config_path('user') == Path.home() / '.codex' / 'config.toml'


def test_get_codex_config_path_repo_scope() -> None:
    repo = Path('/my-repo')
    assert get_codex_config_path('repo', repo) == repo / '.codex' / 'config.toml'


def test_enable_codex_hooks_feature_creates_file(fs: FakeFilesystem) -> None:
    """When config.toml is absent, the file is created with the feature flag."""
    fs.create_dir(Path.home())
    success, message = enable_codex_hooks_feature('user')

    assert success is True
    assert 'codex_hooks' in message

    config_path = Path.home() / '.codex' / 'config.toml'
    assert config_path.exists()
    config = _read_toml(config_path)
    assert config['features']['codex_hooks'] is True


def test_enable_codex_hooks_feature_merges_existing(fs: FakeFilesystem) -> None:
    """Existing non-features keys are preserved."""
    config_dir = Path.home() / '.codex'
    fs.create_dir(config_dir)
    config_path = config_dir / 'config.toml'
    config_path.write_text('model = "gpt-5"\n[features]\nother_flag = true\n')

    success, _ = enable_codex_hooks_feature('user')

    assert success is True
    config = _read_toml(config_path)
    assert config['model'] == 'gpt-5'
    assert config['features']['codex_hooks'] is True
    assert config['features']['other_flag'] is True


def test_enable_codex_hooks_feature_idempotent(fs: FakeFilesystem) -> None:
    """Running the enabler twice leaves the flag in place."""
    fs.create_dir(Path.home())
    enable_codex_hooks_feature('user')
    enable_codex_hooks_feature('user')

    config_path = Path.home() / '.codex' / 'config.toml'
    config = _read_toml(config_path)
    assert config['features']['codex_hooks'] is True


def test_enable_codex_hooks_feature_repo_scope(fs: FakeFilesystem) -> None:
    repo = Path('/workdir/repo')
    fs.create_dir(repo)

    success, _ = enable_codex_hooks_feature('repo', repo_path=repo)

    assert success is True
    config_path = repo / '.codex' / 'config.toml'
    assert config_path.exists()
    config = _read_toml(config_path)
    assert config['features']['codex_hooks'] is True


def test_enable_codex_hooks_feature_handles_malformed_toml(fs: FakeFilesystem) -> None:
    """Malformed existing TOML is reported as failure rather than silently overwritten."""
    config_dir = Path.home() / '.codex'
    fs.create_dir(config_dir)
    (config_dir / 'config.toml').write_text('this is not = [valid toml')

    success, message = enable_codex_hooks_feature('user')

    assert success is False
    assert 'Failed to parse' in message
