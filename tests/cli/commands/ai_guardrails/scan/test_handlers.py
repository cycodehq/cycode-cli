"""Tests for AI guardrails handlers."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import typer

from cycode.cli.apps.ai_guardrails.scan.handlers import (
    handle_before_mcp_execution,
    handle_before_read_file,
    handle_before_submit_prompt,
)
from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.types import AIHookOutcome, BlockReason


@pytest.fixture
def mock_ctx() -> MagicMock:
    """Create a mock Typer context."""
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = {
        'ai_security_client': MagicMock(),
        'scan_type': 'secret',
    }
    return ctx


@pytest.fixture
def mock_payload() -> AIHookPayload:
    """Create a mock AIHookPayload."""
    return AIHookPayload(
        event_name='prompt',
        conversation_id='test-conv-id',
        generation_id='test-gen-id',
        ide_user_email='test@example.com',
        model='gpt-4',
        ide_provider='cursor',
        ide_version='1.0.0',
        prompt='Test prompt',
    )


@pytest.fixture
def default_policy() -> dict[str, Any]:
    """Create a default policy dict."""
    return {
        'mode': 'block',
        'fail_open': True,
        'secrets': {'max_bytes': 200000},
        'prompt': {'enabled': True, 'action': 'block'},
        'file_read': {'enabled': True, 'action': 'block', 'scan_content': True, 'deny_globs': []},
        'mcp': {'enabled': True, 'action': 'block', 'scan_arguments': True},
    }


# Tests for handle_before_submit_prompt


def test_handle_before_submit_prompt_disabled(
    mock_ctx: MagicMock, mock_payload: AIHookPayload, default_policy: dict[str, Any]
) -> None:
    """Test that disabled prompt scanning allows the prompt."""
    default_policy['prompt']['enabled'] = False

    result = handle_before_submit_prompt(mock_ctx, mock_payload, default_policy)

    assert result == {'continue': True}
    mock_ctx.obj['ai_security_client'].create_event.assert_called_once()


@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_text_for_secrets')
def test_handle_before_submit_prompt_no_secrets(
    mock_scan: MagicMock, mock_ctx: MagicMock, mock_payload: AIHookPayload, default_policy: dict[str, Any]
) -> None:
    """Test that prompt with no secrets is allowed."""
    mock_scan.return_value = (None, 'scan-id-123')

    result = handle_before_submit_prompt(mock_ctx, mock_payload, default_policy)

    assert result == {'continue': True}
    mock_ctx.obj['ai_security_client'].create_event.assert_called_once()
    call_args = mock_ctx.obj['ai_security_client'].create_event.call_args
    # outcome is arg[2], scan_id and block_reason are kwargs
    assert call_args.args[2] == AIHookOutcome.ALLOWED
    assert call_args.kwargs['scan_id'] == 'scan-id-123'
    assert call_args.kwargs['block_reason'] is None


@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_text_for_secrets')
def test_handle_before_submit_prompt_with_secrets_blocked(
    mock_scan: MagicMock, mock_ctx: MagicMock, mock_payload: AIHookPayload, default_policy: dict[str, Any]
) -> None:
    """Test that prompt with secrets is blocked."""
    mock_scan.return_value = ('Found 1 secret: API key', 'scan-id-456')

    result = handle_before_submit_prompt(mock_ctx, mock_payload, default_policy)

    assert result['continue'] is False
    assert 'Found 1 secret: API key' in result['user_message']
    mock_ctx.obj['ai_security_client'].create_event.assert_called_once()
    call_args = mock_ctx.obj['ai_security_client'].create_event.call_args
    assert call_args.args[2] == AIHookOutcome.BLOCKED
    assert call_args.kwargs['block_reason'] == BlockReason.SECRETS_IN_PROMPT


@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_text_for_secrets')
def test_handle_before_submit_prompt_with_secrets_warned(
    mock_scan: MagicMock, mock_ctx: MagicMock, mock_payload: AIHookPayload, default_policy: dict[str, Any]
) -> None:
    """Test that prompt with secrets in warn mode is allowed."""
    default_policy['prompt']['action'] = 'warn'
    mock_scan.return_value = ('Found 1 secret: API key', 'scan-id-789')

    result = handle_before_submit_prompt(mock_ctx, mock_payload, default_policy)

    assert result == {'continue': True}
    mock_ctx.obj['ai_security_client'].create_event.assert_called_once()
    call_args = mock_ctx.obj['ai_security_client'].create_event.call_args
    assert call_args.args[2] == AIHookOutcome.WARNED


@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_text_for_secrets')
def test_handle_before_submit_prompt_scan_failure_fail_open(
    mock_scan: MagicMock, mock_ctx: MagicMock, mock_payload: AIHookPayload, default_policy: dict[str, Any]
) -> None:
    """Test that scan failure with fail_open=True allows the prompt."""
    mock_scan.side_effect = RuntimeError('Scan failed')
    default_policy['fail_open'] = True

    with pytest.raises(RuntimeError):
        handle_before_submit_prompt(mock_ctx, mock_payload, default_policy)

    # Event should be tracked even on exception
    mock_ctx.obj['ai_security_client'].create_event.assert_called_once()
    call_args = mock_ctx.obj['ai_security_client'].create_event.call_args
    assert call_args.args[2] == AIHookOutcome.ALLOWED
    # When fail_open=True, no block_reason since action is allowed
    assert call_args.kwargs['block_reason'] is None


@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_text_for_secrets')
def test_handle_before_submit_prompt_scan_failure_fail_closed(
    mock_scan: MagicMock, mock_ctx: MagicMock, mock_payload: AIHookPayload, default_policy: dict[str, Any]
) -> None:
    """Test that scan failure with fail_open=False blocks the prompt."""
    mock_scan.side_effect = RuntimeError('Scan failed')
    default_policy['fail_open'] = False

    with pytest.raises(RuntimeError):
        handle_before_submit_prompt(mock_ctx, mock_payload, default_policy)

    # Event should be tracked even on exception
    mock_ctx.obj['ai_security_client'].create_event.assert_called_once()
    call_args = mock_ctx.obj['ai_security_client'].create_event.call_args
    assert call_args.args[2] == AIHookOutcome.BLOCKED
    assert call_args.kwargs['block_reason'] == BlockReason.SCAN_FAILURE


# Tests for handle_before_read_file


def test_handle_before_read_file_disabled(mock_ctx: MagicMock, default_policy: dict[str, Any]) -> None:
    """Test that disabled file read scanning allows the file."""
    default_policy['file_read']['enabled'] = False
    payload = AIHookPayload(
        event_name='file_read',
        ide_provider='cursor',
        file_path='/path/to/file.txt',
    )

    result = handle_before_read_file(mock_ctx, payload, default_policy)

    assert result == {'permission': 'allow'}


@patch('cycode.cli.apps.ai_guardrails.scan.handlers.is_denied_path')
def test_handle_before_read_file_sensitive_path(
    mock_is_denied: MagicMock, mock_ctx: MagicMock, default_policy: dict[str, Any]
) -> None:
    """Test that sensitive path is blocked."""
    mock_is_denied.return_value = True
    payload = AIHookPayload(
        event_name='file_read',
        ide_provider='cursor',
        file_path='/path/to/.env',
    )

    result = handle_before_read_file(mock_ctx, payload, default_policy)

    assert result['permission'] == 'deny'
    assert '.env' in result['user_message']
    mock_ctx.obj['ai_security_client'].create_event.assert_called_once()
    call_args = mock_ctx.obj['ai_security_client'].create_event.call_args
    assert call_args.args[2] == AIHookOutcome.BLOCKED
    assert call_args.kwargs['block_reason'] == BlockReason.SENSITIVE_PATH


@patch('cycode.cli.apps.ai_guardrails.scan.handlers.is_denied_path')
@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_path_for_secrets')
def test_handle_before_read_file_no_secrets(
    mock_scan: MagicMock, mock_is_denied: MagicMock, mock_ctx: MagicMock, default_policy: dict[str, Any]
) -> None:
    """Test that file with no secrets is allowed."""
    mock_is_denied.return_value = False
    mock_scan.return_value = (None, 'scan-id-123')
    payload = AIHookPayload(
        event_name='file_read',
        ide_provider='cursor',
        file_path='/path/to/file.txt',
    )

    result = handle_before_read_file(mock_ctx, payload, default_policy)

    assert result == {'permission': 'allow'}
    call_args = mock_ctx.obj['ai_security_client'].create_event.call_args
    assert call_args.args[2] == AIHookOutcome.ALLOWED


@patch('cycode.cli.apps.ai_guardrails.scan.handlers.is_denied_path')
@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_path_for_secrets')
def test_handle_before_read_file_with_secrets(
    mock_scan: MagicMock, mock_is_denied: MagicMock, mock_ctx: MagicMock, default_policy: dict[str, Any]
) -> None:
    """Test that file with secrets is blocked."""
    mock_is_denied.return_value = False
    mock_scan.return_value = ('Found 1 secret: password', 'scan-id-456')
    payload = AIHookPayload(
        event_name='file_read',
        ide_provider='cursor',
        file_path='/path/to/file.txt',
    )

    result = handle_before_read_file(mock_ctx, payload, default_policy)

    assert result['permission'] == 'deny'
    assert 'Found 1 secret: password' in result['user_message']
    call_args = mock_ctx.obj['ai_security_client'].create_event.call_args
    assert call_args.args[2] == AIHookOutcome.BLOCKED
    assert call_args.kwargs['block_reason'] == BlockReason.SECRETS_IN_FILE


@patch('cycode.cli.apps.ai_guardrails.scan.handlers.is_denied_path')
@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_path_for_secrets')
def test_handle_before_read_file_scan_disabled(
    mock_scan: MagicMock, mock_is_denied: MagicMock, mock_ctx: MagicMock, default_policy: dict[str, Any]
) -> None:
    """Test that file is allowed when content scanning is disabled."""
    mock_is_denied.return_value = False
    default_policy['file_read']['scan_content'] = False
    payload = AIHookPayload(
        event_name='file_read',
        ide_provider='cursor',
        file_path='/path/to/file.txt',
    )

    result = handle_before_read_file(mock_ctx, payload, default_policy)

    assert result == {'permission': 'allow'}
    mock_scan.assert_not_called()


# Tests for handle_before_mcp_execution


def test_handle_before_mcp_execution_disabled(mock_ctx: MagicMock, default_policy: dict[str, Any]) -> None:
    """Test that disabled MCP scanning allows the execution."""
    default_policy['mcp']['enabled'] = False
    payload = AIHookPayload(
        event_name='mcp_execution',
        ide_provider='cursor',
        mcp_tool_name='test_tool',
        mcp_arguments={'arg1': 'value1'},
    )

    result = handle_before_mcp_execution(mock_ctx, payload, default_policy)

    assert result == {'permission': 'allow'}


@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_text_for_secrets')
def test_handle_before_mcp_execution_no_secrets(
    mock_scan: MagicMock, mock_ctx: MagicMock, default_policy: dict[str, Any]
) -> None:
    """Test that MCP execution with no secrets is allowed."""
    mock_scan.return_value = (None, 'scan-id-123')
    payload = AIHookPayload(
        event_name='mcp_execution',
        ide_provider='cursor',
        mcp_tool_name='test_tool',
        mcp_arguments={'arg1': 'value1'},
    )

    result = handle_before_mcp_execution(mock_ctx, payload, default_policy)

    assert result == {'permission': 'allow'}
    call_args = mock_ctx.obj['ai_security_client'].create_event.call_args
    assert call_args.args[2] == AIHookOutcome.ALLOWED


@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_text_for_secrets')
def test_handle_before_mcp_execution_with_secrets_blocked(
    mock_scan: MagicMock, mock_ctx: MagicMock, default_policy: dict[str, Any]
) -> None:
    """Test that MCP execution with secrets is blocked."""
    mock_scan.return_value = ('Found 1 secret: token', 'scan-id-456')
    payload = AIHookPayload(
        event_name='mcp_execution',
        ide_provider='cursor',
        mcp_tool_name='test_tool',
        mcp_arguments={'arg1': 'secret_token_12345'},
    )

    result = handle_before_mcp_execution(mock_ctx, payload, default_policy)

    assert result['permission'] == 'deny'
    assert 'Found 1 secret: token' in result['user_message']
    call_args = mock_ctx.obj['ai_security_client'].create_event.call_args
    assert call_args.args[2] == AIHookOutcome.BLOCKED
    assert call_args.kwargs['block_reason'] == BlockReason.SECRETS_IN_MCP_ARGS


@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_text_for_secrets')
def test_handle_before_mcp_execution_with_secrets_warned(
    mock_scan: MagicMock, mock_ctx: MagicMock, default_policy: dict[str, Any]
) -> None:
    """Test that MCP execution with secrets in warn mode asks permission."""
    mock_scan.return_value = ('Found 1 secret: token', 'scan-id-789')
    default_policy['mcp']['action'] = 'warn'
    payload = AIHookPayload(
        event_name='mcp_execution',
        ide_provider='cursor',
        mcp_tool_name='test_tool',
        mcp_arguments={'arg1': 'secret_token_12345'},
    )

    result = handle_before_mcp_execution(mock_ctx, payload, default_policy)

    assert result['permission'] == 'ask'
    assert 'Found 1 secret: token' in result['user_message']
    call_args = mock_ctx.obj['ai_security_client'].create_event.call_args
    assert call_args.args[2] == AIHookOutcome.WARNED


@patch('cycode.cli.apps.ai_guardrails.scan.handlers._scan_text_for_secrets')
def test_handle_before_mcp_execution_scan_disabled(
    mock_scan: MagicMock, mock_ctx: MagicMock, default_policy: dict[str, Any]
) -> None:
    """Test that MCP execution is allowed when argument scanning is disabled."""
    default_policy['mcp']['scan_arguments'] = False
    payload = AIHookPayload(
        event_name='mcp_execution',
        ide_provider='cursor',
        mcp_tool_name='test_tool',
        mcp_arguments={'arg1': 'value1'},
    )

    result = handle_before_mcp_execution(mock_ctx, payload, default_policy)

    assert result == {'permission': 'allow'}
    mock_scan.assert_not_called()
