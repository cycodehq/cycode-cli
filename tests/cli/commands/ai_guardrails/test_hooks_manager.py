"""Tests for AI guardrails hooks manager and per-IDE hooks rendering."""

import json
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pyfakefs.fake_filesystem import FakeFilesystem

if TYPE_CHECKING:
    import pytest
    from pytest_mock import MockerFixture

from cycode.cli.apps.ai_guardrails.consts import (
    CYCODE_SCAN_PROMPT_COMMAND,
    CYCODE_SESSION_START_COMMAND,
    PolicyMode,
)
from cycode.cli.apps.ai_guardrails.hooks_manager import (
    create_policy_file,
    install_hooks,
    is_cycode_hook_entry,
    uninstall_hooks,
)
from cycode.cli.apps.ai_guardrails.ides.claude_code import ClaudeCode
from cycode.cli.apps.ai_guardrails.ides.codex import Codex
from cycode.cli.apps.ai_guardrails.ides.copilot import Copilot
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


def test_is_cycode_hook_entry_copilot_shell_fields() -> None:
    # Copilot async entries carry per-OS bash/powershell fields instead of `command`.
    assert is_cycode_hook_entry({'type': 'command', 'bash': 'cycode ai-guardrails scan --ide copilot &'}) is True
    assert is_cycode_hook_entry({'type': 'command', 'powershell': 'cycode ai-guardrails scan --ide copilot'}) is True
    assert is_cycode_hook_entry({'type': 'command', 'bash': '/usr/local/bin/user-hook.sh'}) is False


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


def test_cursor_render_hooks_async(mocker: 'MockerFixture') -> None:
    """Cursor async hooks: '&' suffix on scan commands (unix)."""
    mocker.patch('platform.system', return_value='Linux')
    config = Cursor().render_hooks_config(async_mode=True)
    scan_hooks = {k: v for k, v in config['hooks'].items() if k != 'sessionStart'}
    for entries in scan_hooks.values():
        for entry in entries:
            assert entry['command'].endswith('&')
            assert CYCODE_SCAN_PROMPT_COMMAND in entry['command']


def test_cursor_render_hooks_async_windows_stays_sync(mocker: 'MockerFixture') -> None:
    """No '&' on Windows: cmd treats it as a no-op separator and Windows
    PowerShell rejects it outright - either way nothing detaches."""
    mocker.patch('platform.system', return_value='Windows')
    config = Cursor().render_hooks_config(async_mode=True)
    scan_hooks = {k: v for k, v in config['hooks'].items() if k != 'sessionStart'}
    for entries in scan_hooks.values():
        for entry in entries:
            assert '&' not in entry['command']


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
    """Claude Code SessionStart fires on every source (a forked session reports
    'resume', so the matcher is empty -> match-all)."""
    config = ClaudeCode().render_hooks_config()
    entries = config['hooks']['SessionStart']
    assert len(entries) == 1
    assert 'matcher' not in entries[0]
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


def test_install_preserves_user_hook_colocated_with_cycode(
    fs: FakeFilesystem, monkeypatch: 'pytest.MonkeyPatch'
) -> None:
    """install must not clobber a user-authored hook that shares
    an entry with a Cycode hook. The filter is hook-level, not entry-level.
    """
    repo = Path('/repo')
    fs.create_dir(repo)
    hooks_path = repo / '.codex' / 'hooks.json'
    fs.create_file(
        hooks_path,
        contents=json.dumps(
            {
                'version': 1,
                'hooks': {
                    'SessionStart': [
                        {
                            'matcher': 'startup|clear',
                            'hooks': [
                                {'type': 'command', 'command': '/usr/local/bin/user-debug.sh SessionStart'},
                                {'type': 'command', 'command': 'cycode ai-guardrails session-start --ide codex'},
                            ],
                        }
                    ],
                    # Unrelated event with no Cycode hooks at all — must be untouched.
                    'PostToolUse': [{'hooks': [{'type': 'command', 'command': '/usr/local/bin/user-postlog.sh'}]}],
                },
            }
        ),
    )

    # Codex's post_install touches ~/.codex/config.toml (user scope) — keep that off
    # the filesystem under test by pinning CODEX_HOME inside the fake FS.
    monkeypatch.setenv('CODEX_HOME', '/codex-home')
    fs.create_dir('/codex-home')

    success, _ = install_hooks(Codex(), scope='repo', repo_path=repo)
    assert success is True

    saved = json.loads(hooks_path.read_text())
    session_start = saved['hooks']['SessionStart']
    # The pre-existing entry should still exist with the user hook preserved,
    # and a separate fresh Cycode entry should have been appended.
    user_hook_cmd = '/usr/local/bin/user-debug.sh SessionStart'
    remaining_user_hooks = [
        h for entry in session_start for h in entry.get('hooks', []) if h.get('command') == user_hook_cmd
    ]
    assert remaining_user_hooks, 'user hook was clobbered by install'

    # Unrelated event untouched.
    assert saved['hooks']['PostToolUse'][0]['hooks'][0]['command'] == '/usr/local/bin/user-postlog.sh'


def test_uninstall_preserves_user_hook_colocated_with_cycode(
    fs: FakeFilesystem, monkeypatch: 'pytest.MonkeyPatch'
) -> None:
    """uninstall must strip only the Cycode hook from a mixed entry."""
    repo = Path('/repo')
    fs.create_dir(repo)
    hooks_path = repo / '.codex' / 'hooks.json'
    fs.create_file(
        hooks_path,
        contents=json.dumps(
            {
                'version': 1,
                'hooks': {
                    'UserPromptSubmit': [
                        {
                            'hooks': [
                                {'type': 'command', 'command': '/usr/local/bin/user-debug.sh UserPromptSubmit'},
                                {'type': 'command', 'command': 'cycode ai-guardrails scan --ide codex'},
                            ]
                        }
                    ]
                },
            }
        ),
    )
    monkeypatch.setenv('CODEX_HOME', '/codex-home')
    fs.create_dir('/codex-home')

    success, _ = uninstall_hooks(Codex(), scope='repo', repo_path=repo)
    assert success is True

    saved = json.loads(hooks_path.read_text())
    hooks = saved['hooks']['UserPromptSubmit'][0]['hooks']
    commands = [h['command'] for h in hooks]
    assert '/usr/local/bin/user-debug.sh UserPromptSubmit' in commands
    assert not any('cycode ai-guardrails' in c for c in commands)


def test_copilot_dedicated_file_install_uninstall_lifecycle(fs: FakeFilesystem) -> None:
    """Copilot uses a dedicated Cycode-owned file: install creates it from
    scratch, reinstall is idempotent, uninstall removes the file entirely."""
    copilot = Copilot()
    hooks_path = copilot.settings_path('user')

    success, _ = install_hooks(copilot)
    assert success is True
    saved = json.loads(hooks_path.read_text())
    assert saved['version'] == 1
    assert set(saved['hooks']) == {'sessionStart', 'userPromptSubmitted', 'preToolUse'}
    assert all(len(entries) == 1 for entries in saved['hooks'].values())

    # Reinstall (also flipping mode) must replace, not duplicate.
    success, _ = install_hooks(copilot, report_mode=True)
    assert success is True
    saved = json.loads(hooks_path.read_text())
    assert all(len(entries) == 1 for entries in saved['hooks'].values())
    assert saved['hooks']['preToolUse'][0]['bash'].endswith('&')

    # Uninstall deletes the emptied dedicated file rather than leaving a husk.
    success, _ = uninstall_hooks(copilot)
    assert success is True
    assert not hooks_path.exists()


def test_create_policy_file_repo_scope(fs: FakeFilesystem) -> None:
    """Create a policy file in repo scope."""
    repo_path = Path('/my-repo')
    fs.create_dir(repo_path)

    success, _ = create_policy_file('repo', PolicyMode.WARN, repo_path=repo_path)

    assert success is True
    policy_path = repo_path / '.cycode' / 'ai-guardrails.yaml'
    assert policy_path.exists()
    assert yaml.safe_load(policy_path.read_text())['mode'] == 'warn'
