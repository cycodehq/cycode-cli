"""Tests for AI guardrails hooks manager."""

from pathlib import Path

import yaml
from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.consts import (
    CYCODE_SCAN_PROMPT_COMMAND,
    CYCODE_SESSION_START_COMMAND,
    AIIDEType,
    PolicyMode,
    get_hooks_config,
)
from cycode.cli.apps.ai_guardrails.hooks_manager import create_policy_file, is_cycode_hook_entry


def test_is_cycode_hook_entry_cursor_format() -> None:
    """Test detecting Cycode hook in Cursor format (flat command)."""
    entry = {'command': 'cycode ai-guardrails scan'}
    assert is_cycode_hook_entry(entry) is True

    entry = {'command': 'cycode ai-guardrails scan --some-flag'}
    assert is_cycode_hook_entry(entry) is True


def test_is_cycode_hook_entry_claude_code_format() -> None:
    """Test detecting Cycode hook in Claude Code format (nested)."""
    entry = {
        'hooks': [{'type': 'command', 'command': 'cycode ai-guardrails scan --ide claude-code'}],
    }
    assert is_cycode_hook_entry(entry) is True

    entry = {
        'matcher': 'Read',
        'hooks': [{'type': 'command', 'command': 'cycode ai-guardrails scan --ide claude-code'}],
    }
    assert is_cycode_hook_entry(entry) is True


def test_is_cycode_hook_entry_non_cycode() -> None:
    """Test that non-Cycode hooks are not detected."""
    # Cursor format
    entry = {'command': 'some-other-command'}
    assert is_cycode_hook_entry(entry) is False

    # Claude Code format
    entry = {
        'hooks': [{'type': 'command', 'command': 'some-other-command'}],
    }
    assert is_cycode_hook_entry(entry) is False

    # Empty entry
    entry = {}
    assert is_cycode_hook_entry(entry) is False


def test_is_cycode_hook_entry_partial_match() -> None:
    """Test partial command match."""
    # Should match if command contains 'cycode ai-guardrails scan'
    entry = {'command': '/usr/local/bin/cycode ai-guardrails scan'}
    assert is_cycode_hook_entry(entry) is True

    entry = {'command': 'cycode ai-guardrails scan --verbose'}
    assert is_cycode_hook_entry(entry) is True


def test_get_hooks_config_cursor_sync() -> None:
    """Test Cursor hooks config in default (sync) mode."""
    config = get_hooks_config(AIIDEType.CURSOR)
    hooks = config['hooks']
    scan_hooks = {k: v for k, v in hooks.items() if k != 'sessionStart'}
    for entries in scan_hooks.values():
        for entry in entries:
            assert entry['command'] == CYCODE_SCAN_PROMPT_COMMAND
            assert '&' not in entry['command']


def test_get_hooks_config_cursor_async() -> None:
    """Test Cursor hooks config in async mode appends & to command."""
    config = get_hooks_config(AIIDEType.CURSOR, async_mode=True)
    hooks = config['hooks']
    scan_hooks = {k: v for k, v in hooks.items() if k != 'sessionStart'}
    for entries in scan_hooks.values():
        for entry in entries:
            assert entry['command'].endswith('&')
            assert CYCODE_SCAN_PROMPT_COMMAND in entry['command']


def test_get_hooks_config_cursor_session_start() -> None:
    """Test Cursor hooks config includes sessionStart with --ide flag."""
    config = get_hooks_config(AIIDEType.CURSOR)
    assert 'sessionStart' in config['hooks']
    entries = config['hooks']['sessionStart']
    assert len(entries) == 1
    assert CYCODE_SESSION_START_COMMAND in entries[0]['command']
    assert '--ide cursor' in entries[0]['command']


def test_get_hooks_config_claude_code_sync() -> None:
    """Test Claude Code hooks config in default (sync) mode."""
    config = get_hooks_config(AIIDEType.CLAUDE_CODE)
    scan_events = {k: v for k, v in config['hooks'].items() if k != 'SessionStart'}
    for event_entries in scan_events.values():
        for event_entry in event_entries:
            for hook in event_entry['hooks']:
                assert 'async' not in hook
                assert 'timeout' not in hook


def test_get_hooks_config_claude_code_async() -> None:
    """Test Claude Code hooks config in async mode adds async and timeout."""
    config = get_hooks_config(AIIDEType.CLAUDE_CODE, async_mode=True)
    scan_events = {k: v for k, v in config['hooks'].items() if k != 'SessionStart'}
    for event_entries in scan_events.values():
        for event_entry in event_entries:
            for hook in event_entry['hooks']:
                assert hook['async'] is True


def test_get_hooks_config_claude_code_session_start() -> None:
    """Test Claude Code hooks config includes SessionStart with --ide flag."""
    config = get_hooks_config(AIIDEType.CLAUDE_CODE)
    assert 'SessionStart' in config['hooks']
    entries = config['hooks']['SessionStart']
    assert len(entries) == 1
    assert CYCODE_SESSION_START_COMMAND in entries[0]['hooks'][0]['command']
    assert '--ide claude-code' in entries[0]['hooks'][0]['command']


def test_get_hooks_config_codex_sync() -> None:
    """Test Codex hooks config in default (sync) mode."""
    config = get_hooks_config(AIIDEType.CODEX)
    scan_events = {k: v for k, v in config['hooks'].items() if k != 'SessionStart'}
    for event_entries in scan_events.values():
        for event_entry in event_entries:
            for hook in event_entry['hooks']:
                assert 'async' not in hook
                assert 'timeout' not in hook
                assert '--ide codex' in hook['command']


def test_get_hooks_config_codex_async() -> None:
    """Test Codex hooks config in async mode adds async and timeout."""
    config = get_hooks_config(AIIDEType.CODEX, async_mode=True)
    scan_events = {k: v for k, v in config['hooks'].items() if k != 'SessionStart'}
    for event_entries in scan_events.values():
        for event_entry in event_entries:
            for hook in event_entry['hooks']:
                assert hook['async'] is True


def test_get_hooks_config_codex_session_start() -> None:
    """Test Codex hooks config includes SessionStart auth check."""
    config = get_hooks_config(AIIDEType.CODEX)
    assert 'SessionStart' in config['hooks']
    entries = config['hooks']['SessionStart']
    assert len(entries) == 1
    assert entries[0]['hooks'][0]['command'] == CYCODE_ENSURE_AUTH_COMMAND


def test_get_hooks_config_codex_pretooluse_bash_only() -> None:
    """Test that Codex PreToolUse is scoped to Bash only."""
    config = get_hooks_config(AIIDEType.CODEX)
    pretooluse_entries = config['hooks']['PreToolUse']
    assert len(pretooluse_entries) == 1
    assert pretooluse_entries[0]['matcher'] == 'Bash'


def test_create_policy_file_warn(fs: FakeFilesystem) -> None:
    """Test creating warn-mode policy file."""
    fs.create_dir(Path.home())
    success, message = create_policy_file('user', PolicyMode.WARN)

    assert success is True
    assert 'warn mode' in message

    policy_path = Path.home() / '.cycode' / 'ai-guardrails.yaml'
    assert policy_path.exists()

    policy = yaml.safe_load(policy_path.read_text())
    assert policy['mode'] == 'warn'


def test_create_policy_file_block(fs: FakeFilesystem) -> None:
    """Test creating block-mode policy file."""
    fs.create_dir(Path.home())
    success, message = create_policy_file('user', PolicyMode.BLOCK)

    assert success is True
    assert 'block mode' in message

    policy_path = Path.home() / '.cycode' / 'ai-guardrails.yaml'
    policy = yaml.safe_load(policy_path.read_text())
    assert policy['mode'] == 'block'


def test_create_policy_file_updates_existing(fs: FakeFilesystem) -> None:
    """Test that re-running only updates mode and preserves other customizations."""
    policy_dir = Path.home() / '.cycode'
    fs.create_dir(policy_dir)
    policy_path = policy_dir / 'ai-guardrails.yaml'
    policy_path.write_text(yaml.dump({'version': 1, 'mode': 'warn', 'custom_field': 'keep_me'}))

    success, _ = create_policy_file('user', PolicyMode.BLOCK)

    assert success is True
    policy = yaml.safe_load(policy_path.read_text())
    assert policy['mode'] == 'block'
    assert policy['custom_field'] == 'keep_me'


def test_create_policy_file_repo_scope(fs: FakeFilesystem) -> None:
    """Test creating policy file in repo scope."""
    repo_path = Path('/my-repo')
    fs.create_dir(repo_path)

    success, message = create_policy_file('repo', PolicyMode.WARN, repo_path=repo_path)

    assert success is True
    policy_path = repo_path / '.cycode' / 'ai-guardrails.yaml'
    assert policy_path.exists()

    policy = yaml.safe_load(policy_path.read_text())
    assert policy['mode'] == 'warn'
