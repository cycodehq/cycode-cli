"""Tests for session-start command."""

import json
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.apps.ai_guardrails.session_start_command import session_start_command


@pytest.fixture
def mock_ctx() -> MagicMock:
    """Create a mock Typer context."""
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {}
    return ctx


# Auth tests


@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
def test_already_authenticated_skips_auth(mock_get_auth: MagicMock, mock_ctx: MagicMock) -> None:
    """When already authenticated, AuthManager should not be called."""
    mock_get_auth.return_value = MagicMock()

    with patch('sys.stdin', new=StringIO('')):
        session_start_command(mock_ctx)


@patch('cycode.cli.apps.ai_guardrails.session_start_command.AuthManager')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
def test_not_authenticated_triggers_auth(
    mock_get_auth: MagicMock, mock_auth_manager_cls: MagicMock, mock_ctx: MagicMock
) -> None:
    """When not authenticated, AuthManager.authenticate should be called."""
    mock_get_auth.return_value = None

    with patch('sys.stdin', new=StringIO('')):
        session_start_command(mock_ctx)

    mock_auth_manager_cls.return_value.authenticate.assert_called_once()


@patch('cycode.cli.apps.ai_guardrails.session_start_command.handle_auth_exception')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.AuthManager')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
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


@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
def test_tty_stdin_auth_only(mock_get_auth: MagicMock, mock_ctx: MagicMock) -> None:
    """When stdin is a TTY (old hooks), only auth is performed."""
    mock_get_auth.return_value = MagicMock()
    mock_stdin = MagicMock()
    mock_stdin.isatty.return_value = True

    with patch('sys.stdin', new=mock_stdin):
        session_start_command(mock_ctx)

    mock_stdin.read.assert_not_called()


@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_ai_security_manager_client')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
def test_empty_stdin_skips_session_init(
    mock_get_auth: MagicMock, mock_get_client: MagicMock, mock_ctx: MagicMock
) -> None:
    """Empty stdin should skip session initialization."""
    mock_get_auth.return_value = MagicMock()

    with patch('sys.stdin', new=StringIO('')):
        session_start_command(mock_ctx)

    mock_get_client.assert_not_called()


@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_ai_security_manager_client')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
def test_invalid_json_stdin_skips_session_init(
    mock_get_auth: MagicMock, mock_get_client: MagicMock, mock_ctx: MagicMock
) -> None:
    """Invalid JSON stdin should skip session initialization."""
    mock_get_auth.return_value = MagicMock()

    with patch('sys.stdin', new=StringIO('not valid json')):
        session_start_command(mock_ctx)

    mock_get_client.assert_not_called()


# Conversation creation tests


@patch('cycode.cli.apps.ai_guardrails.session_start_command._extract_from_claude_transcript')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.load_claude_config')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_ai_security_manager_client')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
def test_claude_code_creates_conversation(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_load_config: MagicMock,
    mock_extract: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """Claude Code payload should create conversation with session_id, model, email, version."""
    mock_get_auth.return_value = MagicMock()
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    mock_load_config.return_value = {'oauthAccount': {'emailAddress': 'user@example.com'}}
    mock_extract.return_value = ('2.1.20', 'claude-opus', 'gen-abc')

    payload = {'session_id': 'session-123', 'model': 'claude-opus', 'transcript_path': '/tmp/t.jsonl'}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='claude-code')

    mock_extract.assert_called_once_with('/tmp/t.jsonl')
    mock_ai_client.create_conversation.assert_called_once()
    call_payload = mock_ai_client.create_conversation.call_args[0][0]
    assert call_payload.conversation_id == 'session-123'
    assert call_payload.model == 'claude-opus'
    assert call_payload.ide_user_email == 'user@example.com'
    assert call_payload.ide_provider == 'claude-code'
    assert call_payload.ide_version == '2.1.20'


@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_ai_security_manager_client')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
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


@patch('cycode.cli.apps.ai_guardrails.session_start_command.load_claude_config')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_ai_security_manager_client')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
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


# MCP server reporting tests


@patch('cycode.cli.apps.ai_guardrails.session_start_command.load_claude_config')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_ai_security_manager_client')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
def test_claude_code_reports_mcp_servers(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_load_config: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """Claude Code should report MCP servers from ~/.claude.json."""
    mock_get_auth.return_value = MagicMock()
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    mcp_servers = {
        'gitlab': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-gitlab']},
        'filesystem': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-filesystem']},
    }
    mock_load_config.return_value = {'oauthAccount': {'emailAddress': 'u@e.com'}, 'mcpServers': mcp_servers}

    payload = {'session_id': 'session-123'}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='claude-code')

    mock_ai_client.report_session_context.assert_called_once_with(mcp_servers)


@patch('cycode.cli.apps.ai_guardrails.session_start_command.load_claude_config')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_ai_security_manager_client')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
def test_claude_code_no_mcp_servers_skips_report(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_load_config: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """When no mcpServers in config, report_session_context should not be called."""
    mock_get_auth.return_value = MagicMock()
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    mock_load_config.return_value = {'oauthAccount': {'emailAddress': 'u@e.com'}}

    payload = {'session_id': 'session-123'}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='claude-code')

    mock_ai_client.report_session_context.assert_not_called()


@patch('cycode.cli.apps.ai_guardrails.session_start_command.load_cursor_config')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_ai_security_manager_client')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
def test_cursor_reports_mcp_servers(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_load_cursor: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """Cursor should report MCP servers from ~/.cursor/mcp.json."""
    mock_get_auth.return_value = MagicMock()
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    mcp_servers = {'github': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-github']}}
    mock_load_cursor.return_value = {'mcpServers': mcp_servers}

    payload = {'conversation_id': 'conv-456', 'model': 'gpt-4'}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='cursor')

    mock_ai_client.report_session_context.assert_called_once_with(mcp_servers)


@patch('cycode.cli.apps.ai_guardrails.session_start_command.load_cursor_config')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_ai_security_manager_client')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
def test_cursor_no_mcp_servers_skips_report(
    mock_get_auth: MagicMock,
    mock_get_client: MagicMock,
    mock_load_cursor: MagicMock,
    mock_ctx: MagicMock,
) -> None:
    """Cursor with no MCP config file should skip report_session_context."""
    mock_get_auth.return_value = MagicMock()
    mock_ai_client = MagicMock()
    mock_get_client.return_value = mock_ai_client
    mock_load_cursor.return_value = None

    payload = {'conversation_id': 'conv-456', 'model': 'gpt-4'}

    with patch('sys.stdin', new=StringIO(json.dumps(payload))):
        session_start_command(mock_ctx, ide='cursor')

    mock_ai_client.report_session_context.assert_not_called()



@patch('cycode.cli.apps.ai_guardrails.session_start_command.handle_auth_exception')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.AuthManager')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_ai_security_manager_client')
@patch('cycode.cli.apps.ai_guardrails.session_start_command.get_authorization_info')
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
