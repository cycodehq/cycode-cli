"""Tests for AI guardrails policy loading and management."""

from pathlib import Path
from unittest.mock import patch

from cycode.cli.apps.scan.prompt.policy import (
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

    assert result == {
        'level1': {'level2': {'key1': 'value1', 'key2': 'override2', 'key3': 'value3'}}
    }


def test_deep_merge_override_with_non_dict() -> None:
    """Test that non-dict overrides replace the base value entirely."""
    base = {'key': {'nested': 'value'}}
    override = {'key': 'simple_value'}
    result = deep_merge(base, override)

    assert result == {'key': 'simple_value'}


def test_load_yaml_file_nonexistent(tmp_path: Path) -> None:
    """Test loading a non-existent file returns None."""
    result = load_yaml_file(tmp_path / 'nonexistent.yaml')
    assert result is None


def test_load_yaml_file_valid_yaml(tmp_path: Path) -> None:
    """Test loading a valid YAML file."""
    yaml_file = tmp_path / 'config.yaml'
    yaml_file.write_text('mode: block\nfail_open: true\n')

    result = load_yaml_file(yaml_file)
    assert result == {'mode': 'block', 'fail_open': True}


def test_load_yaml_file_valid_json(tmp_path: Path) -> None:
    """Test loading a valid JSON file."""
    json_file = tmp_path / 'config.json'
    json_file.write_text('{"mode": "block", "fail_open": true}')

    result = load_yaml_file(json_file)
    assert result == {'mode': 'block', 'fail_open': True}


def test_load_yaml_file_invalid_yaml(tmp_path: Path) -> None:
    """Test loading an invalid YAML file returns None."""
    yaml_file = tmp_path / 'invalid.yaml'
    yaml_file.write_text('{ invalid yaml content [')

    result = load_yaml_file(yaml_file)
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


def test_load_policy_defaults_only() -> None:
    """Test loading policy with only defaults (no user or repo config)."""
    with patch('cycode.cli.apps.scan.prompt.policy.load_yaml_file') as mock_load:
        mock_load.return_value = None  # No user or repo config

        policy = load_policy()

        assert 'mode' in policy
        assert 'fail_open' in policy


def test_load_policy_with_user_config(tmp_path: Path) -> None:
    """Test loading policy with user config override."""
    with patch('pathlib.Path.home') as mock_home:
        mock_home.return_value = tmp_path

        # Create user config
        user_config_dir = tmp_path / '.cycode'
        user_config_dir.mkdir()
        user_config = user_config_dir / 'ai-guardrails.yaml'
        user_config.write_text('mode: warn\nfail_open: false\n')

        policy = load_policy()

        # User config should override defaults
        assert policy['mode'] == 'warn'
        assert policy['fail_open'] is False


def test_load_policy_with_repo_config(tmp_path: Path) -> None:
    """Test loading policy with repo config (highest precedence)."""
    # Create repo config
    repo_config_dir = tmp_path / '.cycode'
    repo_config_dir.mkdir()
    repo_config = repo_config_dir / 'ai-guardrails.yaml'
    repo_config.write_text('mode: block\nprompt:\n  enabled: false\n')

    with patch('cycode.cli.apps.scan.prompt.policy.load_yaml_file') as mock_load:
        def side_effect(path: Path):
            if path == repo_config:
                return {'mode': 'block', 'prompt': {'enabled': False}}
            return None

        mock_load.side_effect = side_effect

        policy = load_policy(str(tmp_path))

        # Repo config should have highest precedence
        assert policy['mode'] == 'block'
        assert policy['prompt']['enabled'] is False


def test_load_policy_precedence(tmp_path: Path) -> None:
    """Test that policy precedence is: defaults < user < repo."""
    with patch('pathlib.Path.home') as mock_home:
        mock_home.return_value = tmp_path

        # Create user config
        user_config_dir = tmp_path / '.cycode'
        user_config_dir.mkdir()
        user_config = user_config_dir / 'ai-guardrails.yaml'
        user_config.write_text('mode: warn\nfail_open: false\n')

        # Create repo config in a different location
        repo_path = tmp_path / 'repo'
        repo_path.mkdir()
        repo_config_dir = repo_path / '.cycode'
        repo_config_dir.mkdir()
        repo_config = repo_config_dir / 'ai-guardrails.yaml'
        repo_config.write_text('mode: block\n')  # Override mode but not fail_open

        policy = load_policy(str(repo_path))

        # mode should come from repo (highest precedence)
        assert policy['mode'] == 'block'
        # fail_open should come from user config (repo doesn't override it)
        assert policy['fail_open'] is False


def test_load_policy_none_workspace_root() -> None:
    """Test that None workspace_root is handled correctly."""
    with patch('cycode.cli.apps.scan.prompt.policy.load_yaml_file') as mock_load:
        mock_load.return_value = None

        policy = load_policy(None)

        # Should only load defaults (no repo config)
        assert 'mode' in policy
