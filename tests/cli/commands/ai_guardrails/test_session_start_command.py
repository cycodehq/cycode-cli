"""Tests for session-start command."""

import json
from io import StringIO
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

import pytest
import typer

from cycode.cli.apps.ai_guardrails import session_start_command as _session_start_mod
from cycode.cli.apps.ai_guardrails.ides import IDES, collect_all_session_contexts
from cycode.cli.apps.ai_guardrails.ides import claude_code as _claude_mod
from cycode.cli.apps.ai_guardrails.ides import codex as _codex_mod
from cycode.cli.apps.ai_guardrails.ides import cursor as _cursor_mod
from cycode.cli.apps.ai_guardrails.session_start_command import session_start_command


@pytest.fixture
def mock_ctx() -> MagicMock:
    """Create a mock Typer context."""
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {}
    return ctx


@pytest.fixture(autouse=True)
def _isolated_session_context_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the dedup cache away from the real ~/.cycode in every test."""
    monkeypatch.setattr(_session_start_mod, '_session_context_cache_path', lambda: tmp_path / '.session-context-cache')


# Auth tests


@patch.object(_session_start_mod, 'get_authorization_info')
def test_already_authenticated_skips_auth(mock_get_auth: MagicMock, mock_ctx: MagicMock) -> None:
    """When already authenticated, AuthManager should not be called."""
    mock_get_auth.return_value = MagicMock()

    with patch('sys.stdin', new=StringIO('')):
        session_start_command(mock_ctx)


@patch.object(_session_start_mod, 'AuthManager')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_not_authenticated_triggers_auth(
    mock_get_auth: MagicMock, mock_auth_manager_cls: MagicMock, mock_ctx: MagicMock
) -> None:
    """When not authenticated, AuthManager.authenticate should be called."""
    mock_get_auth.return_value = None

    with patch('sys.stdin', new=StringIO('')):
        session_start_command(mock_ctx)

    mock_auth_manager_cls.return_value.authenticate.assert_called_once()


@patch.object(_session_start_mod, 'handle_auth_exception')
@patch.object(_session_start_mod, 'AuthManager')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_auth_failure_handled_gracefully(
    mock_get_auth: MagicMock,
    mock_auth_manager_cls: MagicMock,
    mock_handle_err: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """Auth failure should be handled gracefully, not crash."""
    mock_get_auth.return_value = None
    mock_auth_manager_cls.return_value.authenticate.side_effect = RuntimeError('auth failed')

    with patch('sys.stdin', new=StringIO('')):
        session_start_command(mock_ctx)

    mock_handle_err.assert_called_once()


# Stdin / payload tests


@patch.object(_session_start_mod, 'get_authorization_info')
def test_tty_stdin_auth_only(mock_get_auth: MagicMock, mock_ctx: MagicMock) -> None:
    """When stdin is a TTY (old hooks), only auth is performed."""
    mock_get_auth.return_value = MagicMock()
    mock_stdin = MagicMock()
    mock_stdin.isatty.return_value = True

    with patch('sys.stdin', new=mock_stdin):
        session_start_command(mock_ctx)

    mock_stdin.read.assert_not_called()


@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_empty_stdin_skips_session_init(
    mock_get_auth: MagicMock, mock_get_client: MagicMock, mock_ctx: MagicMock
) -> None:
    """Empty stdin should skip session initialization."""
    mock_get_auth.return_value = MagicMock()

    with patch('sys.stdin', new=StringIO('')):
        session_start_command(mock_ctx)

    mock_get_client.assert_not_called()


@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_invalid_json_stdin_skips_session_init(
    mock_get_auth: MagicMock, mock_get_client: MagicMock, mock_ctx: MagicMock
) -> None:
    """Invalid JSON stdin should skip session initialization."""
    mock_get_auth.return_value = MagicMock()

    with patch('sys.stdin', new=StringIO('not valid json')):
        session_start_command(mock_ctx)

    mock_get_client.assert_not_called()


# Conversation creation tests


@patch.object(_claude_mod, 'extract_from_claude_transcript')
@patch.object(_claude_mod, 'load_claude_config')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_claude_code_creates_conversation(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_load_config: MagicMock,
    mock_extract: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """Claude Code payload should create a conversation with session_id, model, email, version."""
    mock_get_auth.return_value = MagicMock()
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    mock_load_config.return_value = {'oauthAccount': {'emailAddress': 'user@example.com'}}
    mock_extract.return_value = ('2.1.20', 'claude-opus', 'gen-abc')

    transcript_path = '/fake/transcript.jsonl'
    payload = {'session_id': 'session-123', 'model': 'claude-opus', 'transcript_path': transcript_path}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='claude-code')

    mock_extract.assert_called_once_with(transcript_path)
    mock_ai_client.create_conversation.assert_called_once()
    call_payload = mock_ai_client.create_conversation.call_args[0][0]
    assert call_payload.conversation_id == 'session-123'
    assert call_payload.model == 'claude-opus'
    assert call_payload.ide_user_email == 'user@example.com'
    assert call_payload.ide_provider == 'claude-code'
    assert call_payload.ide_version == '2.1.20'


@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_cursor_creates_conversation(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """Cursor payload should create conversation with conversation_id and model."""
    mock_get_auth.return_value = MagicMock()
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client

    payload = {
        'conversation_id': 'conv-456',
        'user_email': 'cursor-user@example.com',
        'model': 'gpt-4',
        'cursor_version': '0.42.0',
    }

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='cursor')

    mock_ai_client.create_conversation.assert_called_once()
    call_payload = mock_ai_client.create_conversation.call_args[0][0]
    assert call_payload.conversation_id == 'conv-456'
    assert call_payload.model == 'gpt-4'
    assert call_payload.ide_user_email == 'cursor-user@example.com'
    assert call_payload.ide_provider == 'cursor'


@patch.object(_claude_mod, 'load_claude_config')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_conversation_creation_failure_non_blocking(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_load_config: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """Conversation creation failure should not crash the command."""
    mock_get_auth.return_value = MagicMock()
    mock_ai_client = MagicMock()
    mock_ai_client.create_conversation.side_effect = RuntimeError('API down')
    mock_get_client.return_value = mock_ai_client
    mock_load_config.return_value = None

    payload = {'session_id': 'session-123'}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='claude-code')

    # Should not raise


# Session context reporting tests


@patch.object(_claude_mod, 'load_claude_config', return_value={})
@patch.object(_session_start_mod, 'collect_all_session_contexts')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_reports_cross_ide_session_context(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_collect: MagicMock,
    mock_load_config: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """All registered IDEs' configs go into config_files."""
    mock_get_auth.return_value = MagicMock(tenant_id='tenant-1')
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    cursor_file = {'path': '/home/u/.cursor/mcp.json', 'content': '{"mcpServers": {}}'}
    claude_file = {'path': '/home/u/.claude.json', 'content': '{"mcpServers": {}}'}
    plugins = {'dummy-plugin@dummy-marketplace': {'enabled': True}}
    mock_collect.return_value = ({'cursor': cursor_file, 'claude-code': claude_file}, plugins)

    payload = {'session_id': 'session-123'}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='claude-code')

    # config_files is sorted by path for a stable digest.
    mock_ai_client.report_session_context.assert_called_once_with(
        hostname=ANY,
        platform_name=ANY,
        os_version=ANY,
        serial_number=ANY,
        last_login_user=ANY,
        config_files=[claude_file, cursor_file],
        enabled_plugins=plugins,
        user_email=None,
    )


@patch.object(_claude_mod, 'load_claude_config', return_value={})
@patch.object(_session_start_mod, 'collect_all_session_contexts')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_no_mcp_anywhere_still_reports_device(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_collect: MagicMock,
    mock_load_config: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """A machine with no MCP configs or plugins must still report its device context."""
    mock_get_auth.return_value = MagicMock(tenant_id='tenant-1')
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    mock_collect.return_value = ({}, {})

    payload = {'session_id': 'session-123'}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='claude-code')

    mock_ai_client.report_session_context.assert_called_once_with(
        hostname=ANY,
        platform_name=ANY,
        os_version=ANY,
        serial_number=ANY,
        last_login_user=ANY,
        config_files=[],
        enabled_plugins={},
        user_email=None,
    )


@patch.object(_codex_mod, '_load_codex_config')
@patch.object(_cursor_mod, '_load_cursor_mcp_config')
@patch.object(_claude_mod, 'load_claude_settings')
@patch.object(_claude_mod, 'load_claude_config')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_claude_code_reports_global_file_and_plugin_metadata(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_load_config: MagicMock,
    mock_load_settings: MagicMock,
    mock_load_cursor: MagicMock,
    mock_load_codex: MagicMock,
    mock_ctx: MagicMock,
    tmp_path: Path,
) -> None:
    """The global config file carries only the global MCP servers; the plugin's own
    .mcp.json content + path + metadata enrich enabled_plugins (no merge into the global)."""
    mock_get_auth.return_value = MagicMock(tenant_id='tenant-1')
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    mock_load_cursor.return_value = None
    mock_load_codex.return_value = None

    # Set up a fake plugin directory on disk.
    plugin_dir = tmp_path / 'dummy-plugin'
    plugin_dir.mkdir()
    (plugin_dir / '.mcp.json').write_text(
        json.dumps({'mcpServers': {'dummy-server': {'command': 'dummy-command', 'args': ['serve']}}})
    )
    claude_plugin_dir = plugin_dir / '.claude-plugin'
    claude_plugin_dir.mkdir()
    (claude_plugin_dir / 'plugin.json').write_text(
        json.dumps({'name': 'dummy-plugin', 'version': '1.0.28', 'description': 'Dummy plugin'})
    )

    user_mcp_servers = {'dummy-global': {'command': 'dummy-command'}}
    mock_load_config.return_value = {'mcpServers': user_mcp_servers}
    mock_load_settings.return_value = {
        'enabledPlugins': {'dummy-plugin@dummy-marketplace': True},
        'extraKnownMarketplaces': {'dummy-marketplace': {'source': {'source': 'directory', 'path': str(plugin_dir)}}},
    }

    payload = {'session_id': 'session-123'}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='claude-code')

    plugin_mcp = {'mcpServers': {'dummy-server': {'command': 'dummy-command', 'args': ['serve']}}}
    claude_file = {
        'path': str(_claude_mod._CLAUDE_CONFIG_PATH),
        'content': json.dumps({'mcpServers': user_mcp_servers}),
    }
    mock_ai_client.report_session_context.assert_called_once_with(
        hostname=ANY,
        platform_name=ANY,
        os_version=ANY,
        serial_number=ANY,
        last_login_user=ANY,
        config_files=[claude_file],
        enabled_plugins={
            'dummy-plugin@dummy-marketplace': {
                'enabled': True,
                'name': 'dummy-plugin',
                'version': '1.0.28',
                'description': 'Dummy plugin',
                'mcp_server_names': ['dummy-server'],
                'mcp_config_file_path': str(plugin_dir / '.mcp.json'),
                'mcp_config_file': json.dumps(plugin_mcp),
            }
        },
        user_email=None,
    )


@patch.object(_codex_mod, '_load_codex_config')
@patch.object(_claude_mod, 'load_claude_settings')
@patch.object(_claude_mod, 'load_claude_config')
@patch.object(_cursor_mod, '_load_cursor_mcp_config')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_cursor_trigger_sweeps_other_ides(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_load_cursor: MagicMock,
    mock_load_config: MagicMock,
    mock_load_settings: MagicMock,
    mock_load_codex: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """A Cursor-triggered session start also reports Claude's config via config_files."""
    mock_get_auth.return_value = MagicMock(tenant_id='tenant-1')
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    cursor_servers = {'github': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-github']}}
    claude_servers = {'gitlab': {'command': 'npx'}}
    mock_load_cursor.return_value = {'mcpServers': cursor_servers}
    mock_load_config.return_value = {'mcpServers': claude_servers}
    mock_load_settings.return_value = None
    mock_load_codex.return_value = None

    payload = {'conversation_id': 'conv-456', 'model': 'gpt-4'}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='cursor')

    cursor_file = {
        'path': str(Path.home() / '.cursor' / 'mcp.json'),
        'content': json.dumps({'mcpServers': cursor_servers}),
    }
    claude_file = {
        'path': str(_claude_mod._CLAUDE_CONFIG_PATH),
        'content': json.dumps({'mcpServers': claude_servers}),
    }
    # config_files is sorted by path for a stable digest (~/.claude.json < ~/.cursor/mcp.json).
    mock_ai_client.report_session_context.assert_called_once_with(
        hostname=ANY,
        platform_name=ANY,
        os_version=ANY,
        serial_number=ANY,
        last_login_user=ANY,
        config_files=[claude_file, cursor_file],
        enabled_plugins={},
        user_email=None,
    )


# Dedup cache tests


def _run_session_start(mock_ctx: MagicMock, payload: dict) -> None:
    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='claude-code')


@patch.object(_session_start_mod, 'collect_all_session_contexts')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_unchanged_context_skips_second_report(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_collect: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """An identical payload within the TTL is sent once; the second session start skips it."""
    mock_get_auth.return_value = MagicMock(tenant_id='tenant-1')
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    mock_collect.return_value = ({'cursor': {'path': '/p', 'content': 'c'}}, {})

    _run_session_start(mock_ctx, {'session_id': 'session-1'})
    _run_session_start(mock_ctx, {'session_id': 'session-2'})

    mock_ai_client.report_session_context.assert_called_once()


@patch.object(_session_start_mod, 'collect_all_session_contexts')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_changed_context_resends(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_collect: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """A change in the collected inventory busts the cache immediately."""
    mock_get_auth.return_value = MagicMock(tenant_id='tenant-1')
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client

    mock_collect.return_value = ({'cursor': {'path': '/p', 'content': 'c1'}}, {})
    _run_session_start(mock_ctx, {'session_id': 'session-1'})

    mock_collect.return_value = ({'cursor': {'path': '/p', 'content': 'c2'}}, {})
    _run_session_start(mock_ctx, {'session_id': 'session-2'})

    assert mock_ai_client.report_session_context.call_count == 2


@patch.object(_session_start_mod, 'collect_all_session_contexts')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_tenant_change_resends(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_collect: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """Re-authenticating against a different tenant must re-send the same inventory."""
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    mock_collect.return_value = ({'cursor': {'path': '/p', 'content': 'c'}}, {})

    mock_get_auth.return_value = MagicMock(tenant_id='tenant-1')
    _run_session_start(mock_ctx, {'session_id': 'session-1'})

    mock_get_auth.return_value = MagicMock(tenant_id='tenant-2')
    _run_session_start(mock_ctx, {'session_id': 'session-2'})

    assert mock_ai_client.report_session_context.call_count == 2


@patch.object(_session_start_mod, 'collect_all_session_contexts')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_failed_report_is_not_cached(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_collect: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """A failed send must not populate the cache - the next session retries."""
    mock_get_auth.return_value = MagicMock(tenant_id='tenant-1')
    mock_ai_client = MagicMock()
    mock_ai_client.report_session_context.return_value = False
    mock_get_client.return_value = mock_ai_client
    mock_collect.return_value = ({'cursor': {'path': '/p', 'content': 'c'}}, {})

    _run_session_start(mock_ctx, {'session_id': 'session-1'})
    _run_session_start(mock_ctx, {'session_id': 'session-2'})

    assert mock_ai_client.report_session_context.call_count == 2


@patch.object(_session_start_mod, 'collect_all_session_contexts')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_expired_ttl_resends(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_collect: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """After the TTL, an unchanged payload is re-sent (self-healing / liveness heartbeat)."""
    mock_get_auth.return_value = MagicMock(tenant_id='tenant-1')
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    mock_collect.return_value = ({'cursor': {'path': '/p', 'content': 'c'}}, {})

    _run_session_start(mock_ctx, {'session_id': 'session-1'})

    # Age the cache entry past the TTL.
    cache_path = _session_start_mod._session_context_cache_path()
    cache = json.loads(cache_path.read_text(encoding='utf-8'))
    cache['sent_at'] = cache['sent_at'] - _session_start_mod._SESSION_CONTEXT_TTL_SECONDS - 1
    cache_path.write_text(json.dumps(cache), encoding='utf-8')

    _run_session_start(mock_ctx, {'session_id': 'session-2'})

    assert mock_ai_client.report_session_context.call_count == 2


# Cross-IDE sweep tests


def test_collect_all_session_contexts_merges_plugins_first_wins() -> None:
    """A plugin key present in two IDEs keeps the first registered IDE's entry."""
    claude_plugin = {'enabled': True, 'version': '1.0.0'}
    codex_plugin = {'enabled': True, 'version': '2.0.0'}

    with (
        patch.object(IDES['cursor'], 'get_session_context', return_value=(None, {})),
        patch.object(IDES['claude-code'], 'get_session_context', return_value=(None, {'plug@m': claude_plugin})),
        patch.object(IDES['codex'], 'get_session_context', return_value=(None, {'plug@m': codex_plugin})),
    ):
        _, plugins = collect_all_session_contexts()

    assert plugins == {'plug@m': claude_plugin}


@patch.object(_session_start_mod, 'handle_auth_exception')
@patch.object(_session_start_mod, 'AuthManager')
@patch.object(_session_start_mod, 'get_ai_security_manager_client')
@patch.object(_session_start_mod, 'get_authorization_info')
def test_unauthenticated_skips_session_init(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_auth_manager_cls: MagicMock,
    mock_handle_err: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """When auth fails, session initialization should be skipped entirely."""
    mock_get_auth.return_value = None
    mock_auth_manager_cls.return_value.authenticate.side_effect = RuntimeError('auth failed')

    payload = {'session_id': 'session-123'}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='claude-code')

    mock_get_client.assert_not_called()
