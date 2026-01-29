"""Tests for AI hook payload normalization."""

import pytest

from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType


def test_from_cursor_payload_prompt_event() -> None:
    """Test conversion of Cursor beforeSubmitPrompt payload."""
    cursor_payload = {
        'hook_event_name': 'beforeSubmitPrompt',
        'conversation_id': 'conv-123',
        'generation_id': 'gen-456',
        'user_email': 'user@example.com',
        'model': 'gpt-4',
        'cursor_version': '0.42.0',
        'prompt': 'Test prompt',
    }

    unified = AIHookPayload.from_cursor_payload(cursor_payload)

    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.conversation_id == 'conv-123'
    assert unified.generation_id == 'gen-456'
    assert unified.ide_user_email == 'user@example.com'
    assert unified.model == 'gpt-4'
    assert unified.ide_provider == 'cursor'
    assert unified.ide_version == '0.42.0'
    assert unified.prompt == 'Test prompt'


def test_from_cursor_payload_file_read_event() -> None:
    """Test conversion of Cursor beforeReadFile payload."""
    cursor_payload = {
        'hook_event_name': 'beforeReadFile',
        'conversation_id': 'conv-123',
        'file_path': '/path/to/secret.env',
    }

    unified = AIHookPayload.from_cursor_payload(cursor_payload)

    assert unified.event_name == AiHookEventType.FILE_READ
    assert unified.file_path == '/path/to/secret.env'
    assert unified.ide_provider == 'cursor'


def test_from_cursor_payload_mcp_execution_event() -> None:
    """Test conversion of Cursor beforeMCPExecution payload."""
    cursor_payload = {
        'hook_event_name': 'beforeMCPExecution',
        'conversation_id': 'conv-123',
        'command': 'GitLab',
        'tool_name': 'discussion_list',
        'arguments': {'resource_type': 'merge_request', 'parent_id': 'organization/repo', 'resource_id': '4'},
    }

    unified = AIHookPayload.from_cursor_payload(cursor_payload)

    assert unified.event_name == AiHookEventType.MCP_EXECUTION
    assert unified.mcp_server_name == 'GitLab'
    assert unified.mcp_tool_name == 'discussion_list'
    assert unified.mcp_arguments == {
        'resource_type': 'merge_request',
        'parent_id': 'organization/repo',
        'resource_id': '4',
    }


def test_from_cursor_payload_with_alternative_field_names() -> None:
    """Test that alternative field names are handled (path vs file_path, etc.)."""
    cursor_payload = {
        'hook_event_name': 'beforeReadFile',
        'path': '/alternative/path.txt',  # Alternative to file_path
    }

    unified = AIHookPayload.from_cursor_payload(cursor_payload)
    assert unified.file_path == '/alternative/path.txt'

    cursor_payload = {
        'hook_event_name': 'beforeMCPExecution',
        'tool': 'my_tool',  # Alternative to tool_name
        'tool_input': {'key': 'value'},  # Alternative to arguments
    }

    unified = AIHookPayload.from_cursor_payload(cursor_payload)
    assert unified.mcp_tool_name == 'my_tool'
    assert unified.mcp_arguments == {'key': 'value'}


def test_from_cursor_payload_unknown_event() -> None:
    """Test that unknown event names are passed through as-is."""
    cursor_payload = {
        'hook_event_name': 'unknownEvent',
        'conversation_id': 'conv-123',
    }

    unified = AIHookPayload.from_cursor_payload(cursor_payload)
    # Unknown events fall back to original name
    assert unified.event_name == 'unknownEvent'


def test_from_payload_cursor() -> None:
    """Test from_payload dispatcher with Cursor tool."""
    cursor_payload = {
        'hook_event_name': 'beforeSubmitPrompt',
        'prompt': 'test',
    }

    unified = AIHookPayload.from_payload(cursor_payload, tool='cursor')
    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.ide_provider == 'cursor'


def test_from_payload_unsupported_tool() -> None:
    """Test from_payload raises ValueError for unsupported tools."""
    payload = {'hook_event_name': 'someEvent'}

    with pytest.raises(ValueError, match='Unsupported IDE/tool: unsupported'):
        AIHookPayload.from_payload(payload, tool='unsupported')


def test_from_cursor_payload_empty_fields() -> None:
    """Test handling of empty/missing fields."""
    cursor_payload = {
        'hook_event_name': 'beforeSubmitPrompt',
        # Most fields missing
    }

    unified = AIHookPayload.from_cursor_payload(cursor_payload)

    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.conversation_id is None
    assert unified.prompt == ''  # Default to empty string
    assert unified.ide_provider == 'cursor'
