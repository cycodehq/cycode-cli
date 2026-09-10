"""Tests for AI guardrails policy loading and management."""

from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.scan.consts import DEFAULT_POLICY
from cycode.cli.apps.ai_guardrails.scan.policy import (
    deep_merge,
    get_machine_policy_path,
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


def test_load_defaults_carries_knobs_only() -> None:
    """Defaults are operational knobs; enforcement sections come from the platform."""
    defaults = load_defaults()

    assert isinstance(defaults, dict)
    assert 'fail_open' in defaults
    assert 'secrets' in defaults
    assert not {'mode', 'prompt', 'file_read', 'mcp'} & defaults.keys()


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

    assert 'fail_open' in policy
    assert 'secrets' in policy


@patch('pathlib.Path.home')
def test_load_policy_with_user_config(mock_home: MagicMock, fs: FakeFilesystem) -> None:
    """Test loading policy with user config override."""
    mock_home.return_value = Path('/home/testuser')

    # Create user config in fake filesystem
    fs.create_file('/home/testuser/.cycode/ai-guardrails.yaml', contents='mode: warn\nfail_open: false\n')

    policy = load_policy()

    # Knobs merge; `mode` is platform-managed and stripped from local files.
    assert 'mode' not in policy
    assert policy['fail_open'] is False


@patch('cycode.cli.apps.ai_guardrails.scan.policy.load_yaml_file')
def test_load_policy_with_repo_config(mock_load: MagicMock) -> None:
    """Test loading policy with repo config (highest precedence)."""
    repo_path = Path('/fake/repo')
    repo_config = repo_path / '.cycode' / 'ai-guardrails.yaml'

    def side_effect(path: Path) -> Optional[dict]:
        if path == repo_config:
            return {
                'mode': 'block',
                'fail_open': False,
                'prompt': {'enabled': False},
                'file_read': {'deny_globs': ['*.bak'], 'scan_content': False},
                'mcp': {'scan_arguments': False},
            }
        return None

    mock_load.side_effect = side_effect

    policy = load_policy(str(repo_path))

    # Knobs merge from the repo file; nothing a local file says about enforcement survives,
    # so it cannot turn a guardrail off, widen the globs, or skip the content scan.
    assert policy['fail_open'] is False
    assert not {'mode', 'prompt', 'file_read', 'mcp'} & policy.keys()


@patch('pathlib.Path.home')
def test_load_policy_precedence(mock_home: MagicMock, fs: FakeFilesystem) -> None:
    """Test that policy precedence is: defaults < user < repo."""
    mock_home.return_value = Path('/home/testuser')

    # Create user config
    fs.create_file(
        '/home/testuser/.cycode/ai-guardrails.yaml', contents='fail_open: false\nsecrets:\n  max_bytes: 100\n'
    )

    # Create repo config
    fs.create_file('/fake/repo/.cycode/ai-guardrails.yaml', contents='secrets:\n  max_bytes: 200\n')

    policy = load_policy('/fake/repo')

    # max_bytes should come from repo (highest precedence)
    assert policy['secrets']['max_bytes'] == 200
    # fail_open should come from user config (repo doesn't override it)
    assert policy['fail_open'] is False


@patch('cycode.cli.apps.ai_guardrails.scan.policy.load_yaml_file')
def test_load_policy_none_workspace_root(mock_load: MagicMock) -> None:
    """Test that None workspace_root is handled correctly."""
    mock_load.return_value = None

    policy = load_policy(None)

    # Should only load defaults (no repo config)
    assert policy == DEFAULT_POLICY


def test_get_machine_policy_path_per_os(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test the per-OS machine policy locations."""
    with patch('sys.platform', 'darwin'):
        assert get_machine_policy_path() == Path('/Library/Application Support/Cycode') / 'ai-guardrails.yaml'

    with patch('sys.platform', 'linux'):
        assert get_machine_policy_path() == Path('/etc/cycode') / 'ai-guardrails.yaml'

    with patch('sys.platform', 'win32'):
        monkeypatch.setenv('PROGRAMDATA', 'C:\\ProgramData')
        assert get_machine_policy_path() == Path('C:\\ProgramData') / 'Cycode' / 'ai-guardrails.yaml'


@patch('pathlib.Path.home')
@patch('cycode.cli.apps.ai_guardrails.scan.policy.get_machine_policy_path')
def test_load_policy_with_machine_config(
    mock_machine_path: MagicMock, mock_home: MagicMock, fs: FakeFilesystem
) -> None:
    """Test that the machine-wide config overrides defaults."""
    mock_home.return_value = Path('/home/testuser')
    machine_path = Path('/machine/ai-guardrails.yaml')
    mock_machine_path.return_value = machine_path
    fs.create_file(str(machine_path), contents='mode: warn\nsecrets:\n  timeout_ms: 5000\n')

    policy = load_policy()

    # Machine knobs merge; `mode` is platform-managed and stripped from local files.
    assert 'mode' not in policy
    assert policy['secrets']['timeout_ms'] == 5000


@patch('pathlib.Path.home')
@patch('cycode.cli.apps.ai_guardrails.scan.policy.get_machine_policy_path')
def test_load_policy_precedence_defaults_machine_user_repo(
    mock_machine_path: MagicMock, mock_home: MagicMock, fs: FakeFilesystem
) -> None:
    """Test full precedence: defaults < machine < user < repo."""
    mock_home.return_value = Path('/home/testuser')
    machine_path = Path('/machine/ai-guardrails.yaml')
    mock_machine_path.return_value = machine_path
    fs.create_file(str(machine_path), contents='fail_open: false\nsecrets:\n  timeout_ms: 1000\n')
    fs.create_file('/home/testuser/.cycode/ai-guardrails.yaml', contents='fail_open: true\n')
    fs.create_file('/fake/repo/.cycode/ai-guardrails.yaml', contents='secrets:\n  timeout_ms: 3000\n')

    policy = load_policy('/fake/repo')

    # repo overrides machine's timeout; user overrides machine's fail_open.
    assert policy['secrets']['timeout_ms'] == 3000
    assert policy['fail_open'] is True
