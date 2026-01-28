"""Tests for AI guardrails policy loading and management."""

from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.scan.policy import (
    deep_merge,
    get_policy_value,
    load_defaults,
    load_policy,
    load_yaml_file,
)


def test_deep_merge_simple() -> None:
    """Test deep merging two simple dictionaries."""
    base = {'a': 1, 'b': 2}
    override = {'b': 3, 'c': 4}
    result = deep_merge(base, override)

    assert result == {'a': 1, 'b': 3, 'c': 4}


def test_deep_merge_nested() -> None:
    """Test deep merging nested dictionaries."""
    base = {'level1': {'level2': {'key1': 'value1', 'key2': 'value2'}}}
    override = {'level1': {'level2': {'key2': 'override2', 'key3': 'value3'}}}
    result = deep_merge(base, override)

    assert result == {'level1': {'level2': {'key1': 'value1', 'key2': 'override2', 'key3': 'value3'}}}


def test_deep_merge_override_with_non_dict() -> None:
    """Test that non-dict overrides replace the base value entirely."""
    base = {'key': {'nested': 'value'}}
    override = {'key': 'simple_value'}
    result = deep_merge(base, override)

    assert result == {'key': 'simple_value'}


def test_load_yaml_file_nonexistent(fs: FakeFilesystem) -> None:
    """Test loading a non-existent file returns None."""
    result = load_yaml_file(Path('/fake/nonexistent.yaml'))
    assert result is None


def test_load_yaml_file_valid_yaml(fs: FakeFilesystem) -> None:
    """Test loading a valid YAML file."""
    fs.create_file('/fake/config.yaml', contents='mode: block\nfail_open: true\n')

    result = load_yaml_file(Path('/fake/config.yaml'))
    assert result == {'mode': 'block', 'fail_open': True}


def test_load_yaml_file_valid_json(fs: FakeFilesystem) -> None:
    """Test loading a valid JSON file."""
    fs.create_file('/fake/config.json', contents='{"mode": "block", "fail_open": true}')

    result = load_yaml_file(Path('/fake/config.json'))
    assert result == {'mode': 'block', 'fail_open': True}


def test_load_yaml_file_invalid_yaml(fs: FakeFilesystem) -> None:
    """Test loading an invalid YAML file returns None."""
    fs.create_file('/fake/invalid.yaml', contents='{ invalid yaml content [')

    result = load_yaml_file(Path('/fake/invalid.yaml'))
    assert result is None


def test_load_defaults() -> None:
    """Test that load_defaults returns a dict with expected keys."""
    defaults = load_defaults()

    assert isinstance(defaults, dict)
    assert 'mode' in defaults
    assert 'fail_open' in defaults
    assert 'prompt' in defaults
    assert 'file_read' in defaults
    assert 'mcp' in defaults


def test_get_policy_value_single_key() -> None:
    """Test getting a single-level value."""
    policy = {'mode': 'block', 'fail_open': True}

    assert get_policy_value(policy, 'mode') == 'block'
    assert get_policy_value(policy, 'fail_open') is True


def test_get_policy_value_nested_keys() -> None:
    """Test getting a nested value."""
    policy = {'prompt': {'enabled': True, 'action': 'block'}}

    assert get_policy_value(policy, 'prompt', 'enabled') is True
    assert get_policy_value(policy, 'prompt', 'action') == 'block'


def test_get_policy_value_missing_key() -> None:
    """Test that missing keys return the default value."""
    policy = {'mode': 'block'}

    assert get_policy_value(policy, 'nonexistent', default='default_value') == 'default_value'


def test_get_policy_value_deeply_nested() -> None:
    """Test getting deeply nested values."""
    policy = {'level1': {'level2': {'level3': 'value'}}}

    assert get_policy_value(policy, 'level1', 'level2', 'level3') == 'value'
    assert get_policy_value(policy, 'level1', 'level2', 'missing', default='def') == 'def'


def test_get_policy_value_non_dict_in_path() -> None:
    """Test that non-dict values in path return default."""
    policy = {'key': 'string_value'}

    # Trying to access nested key on non-dict should return default
    assert get_policy_value(policy, 'key', 'nested', default='default') == 'default'


@patch('cycode.cli.apps.ai_guardrails.scan.policy.load_yaml_file')
def test_load_policy_defaults_only(mock_load: MagicMock) -> None:
    """Test loading policy with only defaults (no user or repo config)."""
    mock_load.return_value = None  # No user or repo config

    policy = load_policy()

    assert 'mode' in policy
    assert 'fail_open' in policy


@patch('pathlib.Path.home')
def test_load_policy_with_user_config(mock_home: MagicMock, fs: FakeFilesystem) -> None:
    """Test loading policy with user config override."""
    mock_home.return_value = Path('/home/testuser')

    # Create user config in fake filesystem
    fs.create_file('/home/testuser/.cycode/ai-guardrails.yaml', contents='mode: warn\nfail_open: false\n')

    policy = load_policy()

    # User config should override defaults
    assert policy['mode'] == 'warn'
    assert policy['fail_open'] is False


@patch('cycode.cli.apps.ai_guardrails.scan.policy.load_yaml_file')
def test_load_policy_with_repo_config(mock_load: MagicMock) -> None:
    """Test loading policy with repo config (highest precedence)."""
    repo_path = Path('/fake/repo')
    repo_config = repo_path / '.cycode' / 'ai-guardrails.yaml'

    def side_effect(path: Path) -> Optional[dict]:
        if path == repo_config:
            return {'mode': 'block', 'prompt': {'enabled': False}}
        return None

    mock_load.side_effect = side_effect

    policy = load_policy(str(repo_path))

    # Repo config should have highest precedence
    assert policy['mode'] == 'block'
    assert policy['prompt']['enabled'] is False


@patch('pathlib.Path.home')
def test_load_policy_precedence(mock_home: MagicMock, fs: FakeFilesystem) -> None:
    """Test that policy precedence is: defaults < user < repo."""
    mock_home.return_value = Path('/home/testuser')

    # Create user config
    fs.create_file('/home/testuser/.cycode/ai-guardrails.yaml', contents='mode: warn\nfail_open: false\n')

    # Create repo config
    fs.create_file('/fake/repo/.cycode/ai-guardrails.yaml', contents='mode: block\n')

    policy = load_policy('/fake/repo')

    # mode should come from repo (highest precedence)
    assert policy['mode'] == 'block'
    # fail_open should come from user config (repo doesn't override it)
    assert policy['fail_open'] is False


@patch('cycode.cli.apps.ai_guardrails.scan.policy.load_yaml_file')
def test_load_policy_none_workspace_root(mock_load: MagicMock) -> None:
    """Test that None workspace_root is handled correctly."""
    mock_load.return_value = None

    policy = load_policy(None)

    # Should only load defaults (no repo config)
    assert 'mode' in policy
