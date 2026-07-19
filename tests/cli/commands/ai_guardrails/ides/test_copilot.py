"""GitHub Copilot (VS Code) IDE integration tests.

Payload fixtures mirror real events captured from VS Code (built-in Copilot
Chat 0.56.0) and Copilot CLI, with identifying values swapped for dummies.
"""

import json
import os
from pathlib import Path

from pyfakefs.fake_filesystem import FakeFilesystem
from pytest_mock import MockerFixture

from cycode.cli.apps.ai_guardrails.ides.base import HookDecision
from cycode.cli.apps.ai_guardrails.ides.copilot import (
    Copilot,
    _vscode_mcp_config_path,
    split_mcp_tool_name,
)
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType

_VSCODE_PROMPT_PAYLOAD = {
    'timestamp': '2026-07-14T13:32:46.517Z',
    'hook_event_name': 'UserPromptSubmit',
    'session_id': '43cbad91-ea8b-4d4a-9acc-56561421c5d2',
    'prompt': 'test prompt',
}

_VSCODE_READ_FILE_PAYLOAD = {
    'timestamp': '2026-07-14T13:35:08.758Z',
    'hook_event_name': 'PreToolUse',
    'session_id': '43cbad91-ea8b-4d4a-9acc-56561421c5d2',
    'tool_name': 'read_file',
    'tool_input': {'filePath': '/Users/user/.gitconfig', 'startLine': 1, 'endLine': 200},
    'tool_use_id': 'call_dummyDummyDummyDummy__vscode-1784034535752',
}

_VSCODE_MCP_PAYLOAD = {
    'timestamp': '2026-07-14T14:03:57.337Z',
    'hook_event_name': 'PreToolUse',
    'session_id': '43cbad91-ea8b-4d4a-9acc-56561421c5d2',
    'tool_name': 'mcp_gitlab_get_user',
    'tool_input': {'user_id': 'dummy-user'},
    'tool_use_id': 'call_dummyDummyDummyDummy__vscode-1784034535755',
}

_VSCODE_SESSION_START_PAYLOAD = {
    'timestamp': '2026-07-14T13:32:46.474Z',
    'hook_event_name': 'SessionStart',
    'session_id': '43cbad91-ea8b-4d4a-9acc-56561421c5d2',
    'source': 'new',
    'model': 'auto',
}

# Copilot CLI dialect: camelCase, epoch-ms timestamp, no event name, stringified args.
_COPILOT_CLI_TOOL_PAYLOAD = {
    'sessionId': '826a14c1-cfb5-4946-9618-8b0bb7060466',
    'timestamp': 1784038775604,
    'cwd': '/Users/user',
    'toolName': 'view',
    'toolArgs': '{"path": "/Users/user/.zshrc"}',
}

_CLAUDE_CODE_PAYLOAD = {
    'session_id': 'session-123',
    'transcript_path': '/home/user/.claude/projects/transcript.jsonl',
    'cwd': '/Users/user/project',
    'hook_event_name': 'PreToolUse',
    'tool_name': 'Read',
    'tool_input': {'file_path': '/Users/user/.gitconfig'},
    'tool_use_id': 'toolu_dummyDummyDummyDummy',
}


# --- matches_payload ------------------------------------------------------------


def test_matches_payload_accepts_vscode_events() -> None:
    copilot = Copilot()
    assert copilot.matches_payload(_VSCODE_PROMPT_PAYLOAD) is True
    assert copilot.matches_payload(_VSCODE_READ_FILE_PAYLOAD) is True
    assert copilot.matches_payload(_VSCODE_MCP_PAYLOAD) is True


def test_matches_payload_rejects_claude_code_payloads() -> None:
    # Same event names and dialect, but Claude Code always carries transcript_path.
    assert Copilot().matches_payload(_CLAUDE_CODE_PAYLOAD) is False


def test_matches_payload_rejects_copilot_cli_payloads() -> None:
    # CLI dialect is unsupported until its own parsing lands - must skip fail-open.
    assert Copilot().matches_payload(_COPILOT_CLI_TOOL_PAYLOAD) is False


def test_matches_payload_rejects_cursor_payloads() -> None:
    assert Copilot().matches_payload({'hook_event_name': 'beforeSubmitPrompt', 'prompt': 'test'}) is False


def test_matches_payload_requires_timestamp() -> None:
    payload = {k: v for k, v in _VSCODE_PROMPT_PAYLOAD.items() if k != 'timestamp'}
    assert Copilot().matches_payload(payload) is False


# --- parse_hook_payload ---------------------------------------------------------


def test_parse_prompt_payload() -> None:
    unified = Copilot().parse_hook_payload(_VSCODE_PROMPT_PAYLOAD)
    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.conversation_id == '43cbad91-ea8b-4d4a-9acc-56561421c5d2'
    assert unified.ide_provider == 'copilot'
    assert unified.prompt == 'test prompt'


def test_parse_read_file_payload() -> None:
    unified = Copilot().parse_hook_payload(_VSCODE_READ_FILE_PAYLOAD)
    assert unified.event_name == AiHookEventType.FILE_READ
    assert unified.file_path == '/Users/user/.gitconfig'
    assert unified.mcp_tool_name is None


def test_parse_mcp_payload_without_known_servers_reports_raw(fs: FakeFilesystem) -> None:
    # No known servers on disk - honest fallback: no fabricated server, the full
    # unsplit remainder as the tool.
    unified = Copilot().parse_hook_payload(_VSCODE_MCP_PAYLOAD)
    assert unified.event_name == AiHookEventType.MCP_EXECUTION
    assert unified.mcp_server_name is None
    assert unified.mcp_tool_name == 'gitlab_get_user'
    assert unified.mcp_arguments == {'user_id': 'dummy-user'}


def test_parse_mcp_payload_with_known_server_containing_underscores(fs: FakeFilesystem) -> None:
    fs.create_file(
        _vscode_mcp_config_path(),
        contents=json.dumps({'servers': {'gitlab_selfhosted': {'command': 'dummy-mcp'}}}),
    )
    payload = {**_VSCODE_MCP_PAYLOAD, 'tool_name': 'mcp_gitlab_selfhosted_get_user'}
    unified = Copilot().parse_hook_payload(payload)
    assert unified.mcp_server_name == 'gitlab_selfhosted'
    assert unified.mcp_tool_name == 'get_user'


def test_parse_unmatched_tool_passes_raw_tool_name_through() -> None:
    # No matchers in Copilot hooks: unscanned tools must map to an event that
    # matches no handler so scan_command answers with a neutral allow.
    payload = {**_VSCODE_READ_FILE_PAYLOAD, 'tool_name': 'list_dir', 'tool_input': {'path': '/Users/user'}}
    unified = Copilot().parse_hook_payload(payload)
    assert unified.event_name == 'list_dir'
    assert unified.file_path is None
    assert unified.mcp_server_name is None


# --- split_mcp_tool_name --------------------------------------------------------


def test_split_mcp_tool_name_prefers_longest_known_server() -> None:
    servers = ['gitlab', 'gitlab_selfhosted']
    assert split_mcp_tool_name('mcp_gitlab_selfhosted_get_user', servers) == ('gitlab_selfhosted', 'get_user')


def test_split_mcp_tool_name_matches_normalized_config_name() -> None:
    # The wire prefix is the sanitized SELF-REPORTED server name (`DummyTracker` ->
    # `dummytracker`), which resembles the config name modulo separators.
    assert split_mcp_tool_name('mcp_dummytracker_fetch_api', ['dummy-tracker']) == ('dummy-tracker', 'fetch_api')


def test_split_mcp_tool_name_unknown_server_reports_raw() -> None:
    # Self-reported names can diverge entirely from config names (e.g. a server
    # configured as `dummy-plugin` self-reporting `Vendor.DummyApp.Hybrid` yields
    # a sanitized+truncated prefix like `vendor_du`) - never guess a split.
    assert split_mcp_tool_name('mcp_vendor_du_search_instructions', ['dummy-plugin']) == (
        None,
        'vendor_du_search_instructions',
    )


def test_split_mcp_tool_name_server_only() -> None:
    assert split_mcp_tool_name('mcp_gitlab', ['gitlab']) == ('gitlab', None)


# --- build_hook_response --------------------------------------------------------


def test_allow_is_neutral_for_every_event_type() -> None:
    """Allow must be {} - an explicit permissionDecision "allow" would pre-approve
    tools past VS Code's own permission prompts (and with no matchers, that would
    cover every tool, not just scanned ones)."""
    copilot = Copilot()
    for event_type in AiHookEventType:
        assert copilot.build_hook_response(HookDecision.allow(event_type)) == {}


def test_deny_prompt_response_shape() -> None:
    response = Copilot().build_hook_response(HookDecision.deny(AiHookEventType.PROMPT, 'Secrets detected'))
    assert response['decision'] == 'block'
    assert response['reason'] == 'Secrets detected'
    assert response['continue'] is False
    assert response['stopReason'] == 'Secrets detected'


def test_deny_tool_response_shape() -> None:
    response = Copilot().build_hook_response(HookDecision.deny(AiHookEventType.FILE_READ, 'Sensitive file'))
    assert response == {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': 'deny',
            'permissionDecisionReason': 'Sensitive file',
        }
    }


def test_ask_mcp_response_shape() -> None:
    response = Copilot().build_hook_response(HookDecision.ask(AiHookEventType.MCP_EXECUTION, 'Allow execution?'))
    assert response['hookSpecificOutput']['permissionDecision'] == 'ask'
    assert response['hookSpecificOutput']['permissionDecisionReason'] == 'Allow execution?'


# --- render_hooks_config / settings_path ----------------------------------------


def test_render_hooks_config_sync_uses_cross_platform_command() -> None:
    rendered = Copilot().render_hooks_config()
    assert rendered['version'] == 1

    prompt_entry = rendered['hooks']['userPromptSubmitted'][0]
    assert prompt_entry['command'] == 'cycode ai-guardrails scan --ide copilot --event UserPromptSubmit'
    assert 'bash' not in prompt_entry

    tool_entry = rendered['hooks']['preToolUse'][0]
    assert tool_entry['command'] == 'cycode ai-guardrails scan --ide copilot --event PreToolUse'

    session_entry = rendered['hooks']['sessionStart'][0]
    assert session_entry['command'] == 'cycode ai-guardrails session-start --ide copilot'


def test_render_hooks_config_async_backgrounds_on_unix() -> None:
    rendered = Copilot().render_hooks_config(async_mode=True)
    tool_entry = rendered['hooks']['preToolUse'][0]
    assert tool_entry['bash'].endswith('&')
    assert not tool_entry['powershell'].endswith('&')
    assert 'command' not in tool_entry


def test_settings_path_user_scope() -> None:
    path = Copilot().settings_path('user')
    assert path == Path.home() / '.copilot' / 'hooks' / 'cycode.json'


def test_settings_path_honors_copilot_home(mocker: MockerFixture) -> None:
    mocker.patch.dict(os.environ, {'COPILOT_HOME': '/custom/copilot-home'})
    path = Copilot().settings_path('user')
    assert path == Path('/custom/copilot-home') / 'hooks' / 'cycode.json'


def test_settings_path_repo_scope(tmp_path: Path) -> None:
    path = Copilot().settings_path('repo', tmp_path)
    assert path == tmp_path / '.github' / 'hooks' / 'cycode.json'


# --- session payload / context --------------------------------------------------


def test_build_session_payload() -> None:
    session = Copilot().build_session_payload(_VSCODE_SESSION_START_PAYLOAD)
    assert session.ide_provider == 'copilot'
    assert session.conversation_id == '43cbad91-ea8b-4d4a-9acc-56561421c5d2'
    assert session.model == 'auto'
    assert session.source == 'new'


def test_get_session_context_normalizes_servers_key(fs: FakeFilesystem) -> None:
    config_path = _vscode_mcp_config_path()
    fs.create_file(
        config_path,
        contents=json.dumps({'servers': {'gitlab': {'type': 'stdio', 'command': 'dummy-mcp'}}}),
    )

    global_config_file, plugins = Copilot().get_session_context()

    assert global_config_file is not None
    assert global_config_file['path'] == str(config_path)
    # VS Code's `servers` key is normalized to the canonical mcpServers shape.
    assert json.loads(global_config_file['content']) == {
        'mcpServers': {'gitlab': {'type': 'stdio', 'command': 'dummy-mcp'}}
    }
    assert plugins == {}


def test_get_session_context_without_config(fs: FakeFilesystem) -> None:
    assert Copilot().get_session_context() == (None, {})


# --- plugins inventory -----------------------------------------------------------


def _create_plugin_on_disk(
    fs: FakeFilesystem,
    plugin_dir: Path,
    manifest_location: str = '.github/plugin/plugin.json',
    manifest_extra: dict | None = None,
    mcp_file: str = '.mcp.json',
    server_name: str = 'dummy-server',
) -> None:
    manifest = {'name': plugin_dir.name, 'version': '1.0.0', 'description': 'Dummy plugin', **(manifest_extra or {})}
    fs.create_file(plugin_dir / manifest_location, contents=json.dumps(manifest))
    fs.create_file(
        plugin_dir / mcp_file,
        contents=json.dumps({'mcpServers': {server_name: {'command': 'dummy-mcp'}}}),
    )


def test_cli_registry_plugins(fs: FakeFilesystem) -> None:
    """CLI-installed plugins: comment-headed config.json registry, manifest with an
    mcpServers path-ref."""
    plugin_dir = Path.home() / '.copilot' / 'installed-plugins' / 'dummy-marketplace' / 'dummy-plugin'
    _create_plugin_on_disk(fs, plugin_dir, manifest_extra={'mcpServers': './.mcp.json'})
    fs.create_file(
        Path.home() / '.copilot' / 'config.json',
        contents='// This file is managed automatically.\n'
        + json.dumps(
            {
                'installedPlugins': [
                    {
                        'name': 'dummy-plugin',
                        'marketplace': 'dummy-marketplace',
                        'version': '1.0.0',
                        'cache_path': str(plugin_dir),
                        'enabled': True,
                    },
                    {
                        'name': 'disabled-plugin',
                        'marketplace': 'dummy-marketplace',
                        'cache_path': str(plugin_dir),
                        'enabled': False,
                    },
                ]
            }
        ),
    )

    _, plugins = Copilot().get_session_context()

    assert set(plugins) == {'dummy-plugin@dummy-marketplace'}
    entry = plugins['dummy-plugin@dummy-marketplace']
    assert entry['enabled'] is True
    assert entry['version'] == '1.0.0'
    assert entry['mcp_server_names'] == ['dummy-server']
    assert json.loads(entry['mcp_config_file']) == {'mcpServers': {'dummy-server': {'command': 'dummy-mcp'}}}


def test_vscode_registry_plugins(fs: FakeFilesystem) -> None:
    """VS Code UI-installed plugins: installed.json registry with file:// pluginUri,
    root .mcp.json convention without a manifest mcpServers field."""
    plugin_dir = (
        Path.home() / '.vscode' / 'agent-plugins' / 'github.com' / 'dummy-org' / 'repo' / 'plugins' / 'dummy-plugin'
    )
    _create_plugin_on_disk(fs, plugin_dir, manifest_location='.claude-plugin/plugin.json')
    fs.create_file(
        Path.home() / '.vscode' / 'agent-plugins' / 'installed.json',
        contents=json.dumps(
            {
                'version': 1,
                'installed': [
                    {'pluginUri': plugin_dir.as_uri(), 'marketplace': 'dummy-marketplace', 'name': 'dummy-plugin'}
                ],
            }
        ),
    )

    _, plugins = Copilot().get_session_context()

    assert set(plugins) == {'dummy-plugin@dummy-marketplace'}
    assert plugins['dummy-plugin@dummy-marketplace']['mcp_server_names'] == ['dummy-server']


def test_local_dir_plugins_from_plugin_locations_setting(fs: FakeFilesystem) -> None:
    """Local-directory plugins declared via chat.pluginLocations (JSONC settings)."""
    enabled_dir = Path('/plugins/local-plugin')
    disabled_dir = Path('/plugins/disabled-plugin')
    _create_plugin_on_disk(fs, enabled_dir, manifest_location='plugin.json')
    _create_plugin_on_disk(fs, disabled_dir, manifest_location='plugin.json')
    locations = f'{{"{enabled_dir}": true, "{disabled_dir}": false}}'
    fs.create_file(
        _vscode_mcp_config_path().parent / 'settings.json',
        contents=f'{{\n// user settings\n"chat.pluginLocations": {locations}\n}}',
    )

    _, plugins = Copilot().get_session_context()

    assert set(plugins) == {'local-plugin@local'}
    assert plugins['local-plugin@local']['mcp_server_names'] == ['dummy-server']


def test_parse_mcp_payload_matches_plugin_server_via_normalized_name(fs: FakeFilesystem) -> None:
    """End-to-end split: a plugin-declared server named dummy-tracker attributes the
    wire tool mcp_dummytracker_fetch_api (prefix = sanitized self-reported name)."""
    plugin_dir = Path.home() / '.copilot' / 'installed-plugins' / 'dummy-marketplace' / 'dummy-tracker'
    _create_plugin_on_disk(fs, plugin_dir, server_name='dummy-tracker')
    fs.create_file(
        Path.home() / '.copilot' / 'config.json',
        contents=json.dumps(
            {
                'installedPlugins': [
                    {'name': 'dummy-tracker', 'marketplace': 'dummy-marketplace', 'cache_path': str(plugin_dir)}
                ]
            }
        ),
    )

    payload = {**_VSCODE_MCP_PAYLOAD, 'tool_name': 'mcp_dummytracker_fetch_api', 'tool_input': {'key': 'payments'}}
    unified = Copilot().parse_hook_payload(payload)

    assert unified.mcp_server_name == 'dummy-tracker'
    assert unified.mcp_tool_name == 'fetch_api'
