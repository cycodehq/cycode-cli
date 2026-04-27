"""Tests for AI hook payload normalization."""

import pytest
from pytest_mock import MockerFixture

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
    assert type(unified.ide_provider) is str


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


# Claude Code payload tests


def test_from_claude_code_payload_prompt_event() -> None:
    """Test conversion of Claude Code UserPromptSubmit payload."""
    claude_payload = {
        'hook_event_name': 'UserPromptSubmit',
        'session_id': 'session-123',
        'prompt': 'Test prompt for Claude Code',
    }

    unified = AIHookPayload.from_claude_code_payload(claude_payload)

    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.conversation_id == 'session-123'
    assert unified.ide_provider == 'claude-code'
    assert unified.prompt == 'Test prompt for Claude Code'
    assert type(unified.ide_provider) is str


def test_from_claude_code_payload_file_read_event() -> None:
    """Test conversion of Claude Code PreToolUse with Read tool."""
    claude_payload = {
        'hook_event_name': 'PreToolUse',
        'session_id': 'session-456',
        'tool_name': 'Read',
        'tool_input': {'file_path': '/path/to/secret.env'},
    }

    unified = AIHookPayload.from_claude_code_payload(claude_payload)

    assert unified.event_name == AiHookEventType.FILE_READ
    assert unified.file_path == '/path/to/secret.env'
    assert unified.ide_provider == 'claude-code'
    assert unified.mcp_tool_name is None


def test_from_claude_code_payload_mcp_execution_event() -> None:
    """Test conversion of Claude Code PreToolUse with MCP tool."""
    claude_payload = {
        'hook_event_name': 'PreToolUse',
        'session_id': 'session-789',
        'tool_name': 'mcp__gitlab__discussion_list',
        'tool_input': {'resource_type': 'merge_request', 'parent_id': 'org/repo', 'resource_id': '4'},
    }

    unified = AIHookPayload.from_payload(claude_payload, tool='claude-code')

    assert unified.event_name == AiHookEventType.MCP_EXECUTION
    assert unified.mcp_server_name == 'gitlab'
    assert unified.mcp_tool_name == 'discussion_list'
    assert unified.mcp_arguments == {'resource_type': 'merge_request', 'parent_id': 'org/repo', 'resource_id': '4'}
    assert unified.ide_provider == 'claude-code'


def test_from_claude_code_payload_empty_fields() -> None:
    """Test handling of empty/missing fields for Claude Code."""
    claude_payload = {
        'hook_event_name': 'UserPromptSubmit',
        # Most fields missing
    }

    unified = AIHookPayload.from_claude_code_payload(claude_payload)

    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.conversation_id is None
    assert unified.prompt == ''  # Default to empty string
    assert unified.ide_provider == 'claude-code'


# Claude Code transcript extraction tests


def test_from_claude_code_payload_extracts_from_transcript(mocker: MockerFixture) -> None:
    """Test that version, model, and generation_id are extracted from transcript file."""
    transcript_content = (
        b'{"type":"user","version":"2.1.20","uuid":"user-uuid-1","message":{"role":"user","content":"hello"}}\n'
        b'{"type":"assistant","message":{"model":"claude-opus-4-5-20251101","role":"assistant",'
        b'"content":[{"type":"text","text":"Hi!"}]},"uuid":"assistant-uuid-1"}\n'
        b'{"type":"user","version":"2.1.20","uuid":"user-uuid-2","message":{"role":"user","content":"test prompt"}}\n'
    )
    mock_path = mocker.patch('cycode.cli.apps.ai_guardrails.scan.payload.Path')
    mock_path.return_value.exists.return_value = True
    mock_path.return_value.open.return_value.__enter__.return_value.seek = mocker.Mock()
    mock_path.return_value.open.return_value.__enter__.return_value.tell.return_value = len(transcript_content)
    mock_path.return_value.open.return_value.__enter__.return_value.read.return_value = transcript_content

    claude_payload = {
        'hook_event_name': 'UserPromptSubmit',
        'session_id': 'session-123',
        'prompt': 'test prompt',
        'transcript_path': '/mock/transcript.jsonl',
    }

    unified = AIHookPayload.from_claude_code_payload(claude_payload)

    assert unified.ide_version == '2.1.20'
    assert unified.model == 'claude-opus-4-5-20251101'
    assert unified.generation_id == 'user-uuid-2'


def test_from_claude_code_payload_handles_missing_transcript(mocker: MockerFixture) -> None:
    """Test that missing transcript file doesn't break payload parsing."""
    mock_path = mocker.patch('cycode.cli.apps.ai_guardrails.scan.payload.Path')
    mock_path.return_value.exists.return_value = False

    claude_payload = {
        'hook_event_name': 'UserPromptSubmit',
        'session_id': 'session-123',
        'prompt': 'test',
        'transcript_path': '/nonexistent/path/transcript.jsonl',
    }

    unified = AIHookPayload.from_claude_code_payload(claude_payload)

    assert unified.ide_version is None
    assert unified.model is None
    assert unified.generation_id is None
    assert unified.conversation_id == 'session-123'
    assert unified.prompt == 'test'


def test_from_claude_code_payload_handles_no_transcript_path() -> None:
    """Test that absent transcript_path doesn't break payload parsing."""
    claude_payload = {
        'hook_event_name': 'UserPromptSubmit',
        'session_id': 'session-123',
        'prompt': 'test',
    }

    unified = AIHookPayload.from_claude_code_payload(claude_payload)

    assert unified.ide_version is None
    assert unified.model is None
    assert unified.generation_id is None


def test_from_claude_code_payload_extracts_model_from_nested_message(mocker: MockerFixture) -> None:
    """Test that model is extracted from nested message.model field."""
    transcript_content = (
        b'{"type":"assistant","message":{"model":"claude-sonnet-4-20250514",'
        b'"role":"assistant","content":[]},"uuid":"uuid-1"}\n'
    )

    mock_path = mocker.patch('cycode.cli.apps.ai_guardrails.scan.payload.Path')
    mock_path.return_value.exists.return_value = True
    mock_path.return_value.open.return_value.__enter__.return_value.seek = mocker.Mock()
    mock_path.return_value.open.return_value.__enter__.return_value.tell.return_value = len(transcript_content)
    mock_path.return_value.open.return_value.__enter__.return_value.read.return_value = transcript_content

    claude_payload = {
        'hook_event_name': 'UserPromptSubmit',
        'prompt': 'test',
        'transcript_path': '/mock/transcript.jsonl',
    }

    unified = AIHookPayload.from_claude_code_payload(claude_payload)

    assert unified.model == 'claude-sonnet-4-20250514'


def test_from_claude_code_payload_gets_latest_user_uuid(mocker: MockerFixture) -> None:
    """Test that generation_id is the UUID of the latest user message."""
    transcript_content = b"""{"type":"user","uuid":"old-user-uuid","message":{"role":"user","content":"first"}}
{"type":"assistant","uuid":"assistant-uuid","message":{"role":"assistant","content":[]}}
{"type":"user","uuid":"latest-user-uuid","message":{"role":"user","content":"second"}}
{"type":"assistant","uuid":"last-assistant-uuid","message":{"role":"assistant","content":[]}}
"""
    mock_path = mocker.patch('cycode.cli.apps.ai_guardrails.scan.payload.Path')
    mock_path.return_value.exists.return_value = True
    mock_path.return_value.open.return_value.__enter__.return_value.seek = mocker.Mock()
    mock_path.return_value.open.return_value.__enter__.return_value.tell.return_value = len(transcript_content)
    mock_path.return_value.open.return_value.__enter__.return_value.read.return_value = transcript_content

    claude_payload = {
        'hook_event_name': 'UserPromptSubmit',
        'prompt': 'test',
        'transcript_path': '/mock/transcript.jsonl',
    }

    unified = AIHookPayload.from_claude_code_payload(claude_payload)

    assert unified.generation_id == 'latest-user-uuid'


# Claude Code email extraction tests


def test_from_claude_code_payload_extracts_email_from_config(mocker: MockerFixture) -> None:
    """Test that ide_user_email is populated from ~/.claude.json."""
    mocker.patch(
        'cycode.cli.apps.ai_guardrails.scan.payload.load_claude_config',
        return_value={'oauthAccount': {'emailAddress': 'user@example.com'}},
    )

    claude_payload = {
        'hook_event_name': 'UserPromptSubmit',
        'session_id': 'session-123',
        'prompt': 'test',
    }

    unified = AIHookPayload.from_claude_code_payload(claude_payload)
    assert unified.ide_user_email == 'user@example.com'


def test_from_claude_code_payload_email_none_when_config_missing(mocker: MockerFixture) -> None:
    """Test that ide_user_email is None when ~/.claude.json is missing."""
    mocker.patch(
        'cycode.cli.apps.ai_guardrails.scan.payload.load_claude_config',
        return_value=None,
    )

    claude_payload = {
        'hook_event_name': 'UserPromptSubmit',
        'session_id': 'session-123',
        'prompt': 'test',
    }

    unified = AIHookPayload.from_claude_code_payload(claude_payload)
    assert unified.ide_user_email is None


def test_from_claude_code_payload_email_none_when_no_oauth(mocker: MockerFixture) -> None:
    """Test that ide_user_email is None when oauthAccount is missing from config."""
    mocker.patch(
        'cycode.cli.apps.ai_guardrails.scan.payload.load_claude_config',
        return_value={'someOtherKey': 'value'},
    )

    claude_payload = {
        'hook_event_name': 'UserPromptSubmit',
        'session_id': 'session-123',
        'prompt': 'test',
    }

    unified = AIHookPayload.from_claude_code_payload(claude_payload)
    assert unified.ide_user_email is None


# IDE detection tests


def test_is_payload_for_ide_claude_code_matches_claude_code() -> None:
    """Test that Claude Code events match when expected IDE is claude-code."""
    payload = {'hook_event_name': 'UserPromptSubmit'}
    assert AIHookPayload.is_payload_for_ide(payload, 'claude-code') is True

    payload = {'hook_event_name': 'PreToolUse'}
    assert AIHookPayload.is_payload_for_ide(payload, 'claude-code') is True


def test_is_payload_for_ide_cursor_matches_cursor() -> None:
    """Test that Cursor events match when expected IDE is cursor."""
    payload = {'hook_event_name': 'beforeSubmitPrompt'}
    assert AIHookPayload.is_payload_for_ide(payload, 'cursor') is True

    payload = {'hook_event_name': 'beforeReadFile'}
    assert AIHookPayload.is_payload_for_ide(payload, 'cursor') is True

    payload = {'hook_event_name': 'beforeMCPExecution'}
    assert AIHookPayload.is_payload_for_ide(payload, 'cursor') is True


def test_is_payload_for_ide_claude_code_does_not_match_cursor() -> None:
    """Test that Claude Code events don't match when expected IDE is cursor.

    This prevents double-processing when Cursor reads Claude Code hooks.
    """
    payload = {'hook_event_name': 'UserPromptSubmit'}
    assert AIHookPayload.is_payload_for_ide(payload, 'cursor') is False

    payload = {'hook_event_name': 'PreToolUse'}
    assert AIHookPayload.is_payload_for_ide(payload, 'cursor') is False


def test_is_payload_for_ide_cursor_does_not_match_claude_code() -> None:
    """Test that Cursor events don't match when expected IDE is claude-code."""
    payload = {'hook_event_name': 'beforeSubmitPrompt'}
    assert AIHookPayload.is_payload_for_ide(payload, 'claude-code') is False

    payload = {'hook_event_name': 'beforeReadFile'}
    assert AIHookPayload.is_payload_for_ide(payload, 'claude-code') is False


def test_is_payload_for_ide_empty_event_name() -> None:
    """Test handling of empty or missing hook_event_name."""
    payload = {'hook_event_name': ''}
    assert AIHookPayload.is_payload_for_ide(payload, 'cursor') is False
    assert AIHookPayload.is_payload_for_ide(payload, 'claude-code') is False

    payload = {}
    assert AIHookPayload.is_payload_for_ide(payload, 'cursor') is False
    assert AIHookPayload.is_payload_for_ide(payload, 'claude-code') is False


# Codex payload tests


def test_from_codex_payload_prompt_event() -> None:
    """Test conversion of Codex UserPromptSubmit payload."""
    codex_payload = {
        'hook_event_name': 'UserPromptSubmit',
        'session_id': 'session-abc',
        'turn_id': 'turn-1',
        'cwd': '/workspace',
        'model': 'gpt-5',
        'prompt': 'Hi Codex',
    }

    unified = AIHookPayload.from_codex_payload(codex_payload)

    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.conversation_id == 'session-abc'
    assert unified.generation_id == 'turn-1'
    assert unified.model == 'gpt-5'
    assert unified.ide_provider == 'codex'
    assert unified.prompt == 'Hi Codex'
    assert unified.command is None


def test_from_codex_payload_bash_command_event() -> None:
    """Test conversion of Codex PreToolUse:Bash payload."""
    codex_payload = {
        'hook_event_name': 'PreToolUse',
        'session_id': 'session-abc',
        'turn_id': 'turn-2',
        'cwd': '/workspace',
        'model': 'gpt-5',
        'tool_name': 'Bash',
        'tool_use_id': 'u1',
        'tool_input': {'command': 'curl https://evil.example'},
    }

    unified = AIHookPayload.from_codex_payload(codex_payload)

    assert unified.event_name == AiHookEventType.COMMAND_EXEC
    assert unified.command == 'curl https://evil.example'
    assert unified.ide_provider == 'codex'
    assert unified.file_path is None
    assert unified.mcp_tool_name is None


def test_from_codex_payload_unknown_event() -> None:
    """Test that unknown Codex events fall back to raw event name."""
    codex_payload = {'hook_event_name': 'PostToolUse'}
    unified = AIHookPayload.from_codex_payload(codex_payload)
    # PostToolUse isn't in our canonical mapping; preserved as-is
    assert unified.event_name == 'PostToolUse'


def test_is_payload_for_ide_codex_matches() -> None:
    """Test that Codex events match the Codex IDE."""
    payload = {'hook_event_name': 'UserPromptSubmit'}
    assert AIHookPayload.is_payload_for_ide(payload, 'codex') is True

    payload = {'hook_event_name': 'PreToolUse'}
    assert AIHookPayload.is_payload_for_ide(payload, 'codex') is True


def test_is_payload_for_ide_cursor_does_not_match_codex() -> None:
    """Test that Cursor events don't match when expected IDE is codex."""
    payload = {'hook_event_name': 'beforeSubmitPrompt'}
    assert AIHookPayload.is_payload_for_ide(payload, 'codex') is False


def test_from_payload_dispatches_codex() -> None:
    """Test that from_payload dispatcher routes Codex payloads correctly."""
    codex_payload = {
        'hook_event_name': 'UserPromptSubmit',
        'session_id': 's1',
        'prompt': 'test',
    }

    unified = AIHookPayload.from_payload(codex_payload, tool='codex')
    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.ide_provider == 'codex'
