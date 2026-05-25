"""Tests for AI guardrails hooks manager and per-IDE hooks rendering."""

from pathlib import Path

import yaml
from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.consts import (
    CYCODE_SCAN_PROMPT_COMMAND,
    CYCODE_SESSION_START_COMMAND,
    PolicyMode,
)
from cycode.cli.apps.ai_guardrails.hooks_manager import create_policy_file, is_cycode_hook_entry
from cycode.cli.apps.ai_guardrails.ides.claude_code import ClaudeCode
from cycode.cli.apps.ai_guardrails.ides.cursor import Cursor


def test_is_cycode_hook_entry_cursor_format() -> None:
    """Detect Cycode hook in Cursor's flat command format."""
    assert is_cycode_hook_entry({'command': 'cycode ai-guardrails scan'}) is True
    assert is_cycode_hook_entry({'command': 'cycode ai-guardrails scan --some-flag'}) is True


def test_is_cycode_hook_entry_claude_code_format() -> None:
    """Detect Cycode hook in Claude Code's nested format."""
    entry = {'hooks': [{'type': 'command', 'command': 'cycode ai-guardrails scan --ide claude-code'}]}
    assert is_cycode_hook_entry(entry) is True

    entry = {
        'matcher': 'Read',
        'hooks': [{'type': 'command', 'command': 'cycode ai-guardrails scan --ide claude-code'}],
    }
    assert is_cycode_hook_entry(entry) is True


def test_is_cycode_hook_entry_non_cycode() -> None:
    """Non-Cycode hooks must not be detected."""
    assert is_cycode_hook_entry({'command': 'some-other-command'}) is False
    assert is_cycode_hook_entry({'hooks': [{'type': 'command', 'command': 'some-other-command'}]}) is False
    assert is_cycode_hook_entry({}) is False


def test_is_cycode_hook_entry_partial_match() -> None:
    """Detection is substring-based: full paths and trailing flags still count."""
    assert is_cycode_hook_entry({'command': '/usr/local/bin/cycode ai-guardrails scan'}) is True
    assert is_cycode_hook_entry({'command': 'cycode ai-guardrails scan --verbose'}) is True


# Per-IDE hook config tests (now exposed via IDE.render_hooks_config)


def test_cursor_render_hooks_sync() -> None:
    """Cursor sync hooks: no '&' in scan commands."""
    config = Cursor().render_hooks_config()
    scan_hooks = {k: v for k, v in config['hooks'].items() if k != 'sessionStart'}
    for entries in scan_hooks.values():
        for entry in entries:
            assert entry['command'] == CYCODE_SCAN_PROMPT_COMMAND
            assert '&' not in entry['command']


def test_cursor_render_hooks_async() -> None:
    """Cursor async hooks: '&' suffix on scan commands."""
    config = Cursor().render_hooks_config(async_mode=True)
    scan_hooks = {k: v for k, v in config['hooks'].items() if k != 'sessionStart'}
    for entries in scan_hooks.values():
        for entry in entries:
            assert entry['command'].endswith('&')
            assert CYCODE_SCAN_PROMPT_COMMAND in entry['command']


def test_cursor_render_hooks_session_start() -> None:
    """Cursor session_start carries the --ide flag explicitly."""
    config = Cursor().render_hooks_config()
    assert 'sessionStart' in config['hooks']
    entries = config['hooks']['sessionStart']
    assert len(entries) == 1
    assert CYCODE_SESSION_START_COMMAND in entries[0]['command']
    assert '--ide cursor' in entries[0]['command']


def test_claude_code_render_hooks_sync() -> None:
    """Claude Code sync hooks: no async/timeout fields."""
    config = ClaudeCode().render_hooks_config()
    scan_events = {k: v for k, v in config['hooks'].items() if k != 'SessionStart'}
    for event_entries in scan_events.values():
        for event_entry in event_entries:
            for hook in event_entry['hooks']:
                assert 'async' not in hook
                assert 'timeout' not in hook


def test_claude_code_render_hooks_async() -> None:
    """Claude Code async hooks: 'async' flag + timeout."""
    config = ClaudeCode().render_hooks_config(async_mode=True)
    scan_events = {k: v for k, v in config['hooks'].items() if k != 'SessionStart'}
    for event_entries in scan_events.values():
        for event_entry in event_entries:
            for hook in event_entry['hooks']:
                assert hook['async'] is True


def test_claude_code_render_hooks_session_start() -> None:
    """Claude Code SessionStart carries the --ide flag explicitly."""
    config = ClaudeCode().render_hooks_config()
    assert 'SessionStart' in config['hooks']
    entries = config['hooks']['SessionStart']
    assert len(entries) == 1
    assert CYCODE_SESSION_START_COMMAND in entries[0]['hooks'][0]['command']
    assert '--ide claude-code' in entries[0]['hooks'][0]['command']


# Policy file tests


def test_create_policy_file_warn(fs: FakeFilesystem) -> None:
    """Create a warn-mode policy file."""
    fs.create_dir(Path.home())
    success, message = create_policy_file('user', PolicyMode.WARN)

    assert success is True
    assert 'warn mode' in message

    policy_path = Path.home() / '.cycode' / 'ai-guardrails.yaml'
    assert policy_path.exists()
    assert yaml.safe_load(policy_path.read_text())['mode'] == 'warn'


def test_create_policy_file_block(fs: FakeFilesystem) -> None:
    """Create a block-mode policy file."""
    fs.create_dir(Path.home())
    success, message = create_policy_file('user', PolicyMode.BLOCK)

    assert success is True
    assert 'block mode' in message

    policy_path = Path.home() / '.cycode' / 'ai-guardrails.yaml'
    assert yaml.safe_load(policy_path.read_text())['mode'] == 'block'


def test_create_policy_file_updates_existing(fs: FakeFilesystem) -> None:
    """Re-running updates only the mode field and preserves customizations."""
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
    """Create a policy file in repo scope."""
    repo_path = Path('/my-repo')
    fs.create_dir(repo_path)

    success, _ = create_policy_file('repo', PolicyMode.WARN, repo_path=repo_path)

    assert success is True
    policy_path = repo_path / '.cycode' / 'ai-guardrails.yaml'
    assert policy_path.exists()
    assert yaml.safe_load(policy_path.read_text())['mode'] == 'warn'
