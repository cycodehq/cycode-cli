"""Cursor IDE integration tests (payload parsing, response building, MCP context)."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cycode.cli.apps.ai_guardrails.ides.base import HookDecision
from cycode.cli.apps.ai_guardrails.ides.cursor import Cursor
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType


def test_matches_payload_only_cursor_events() -> None:
    cursor = Cursor()
    assert cursor.matches_payload({'hook_event_name': 'beforeSubmitPrompt'}) is True
    assert cursor.matches_payload({'hook_event_name': 'beforeReadFile'}) is True
    assert cursor.matches_payload({'hook_event_name': 'beforeMCPExecution'}) is True
    assert cursor.matches_payload({'hook_event_name': 'UserPromptSubmit'}) is False
    assert cursor.matches_payload({'hook_event_name': 'PreToolUse'}) is False


def test_parse_prompt_payload() -> None:
    payload = {
        'hook_event_name': 'beforeSubmitPrompt',
        'conversation_id': 'conv-123',
        'generation_id': 'gen-456',
        'user_email': 'user@example.com',
        'model': 'gpt-4',
        'cursor_version': '0.42.0',
        'prompt': 'Test prompt',
    }
    unified = Cursor().parse_hook_payload(payload)

    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.conversation_id == 'conv-123'
    assert unified.generation_id == 'gen-456'
    assert unified.ide_user_email == 'user@example.com'
    assert unified.model == 'gpt-4'
    assert unified.ide_provider == 'cursor'
    assert unified.ide_version == '0.42.0'
    assert unified.prompt == 'Test prompt'


def test_parse_file_read_payload() -> None:
    unified = Cursor().parse_hook_payload({'hook_event_name': 'beforeReadFile', 'file_path': '/path/to/secret.env'})
    assert unified.event_name == AiHookEventType.FILE_READ
    assert unified.file_path == '/path/to/secret.env'


def test_parse_mcp_execution_payload() -> None:
    args: dict[str, Any] = {'resource_type': 'merge_request', 'parent_id': 'org/repo', 'resource_id': '4'}
    unified = Cursor().parse_hook_payload(
        {
            'hook_event_name': 'beforeMCPExecution',
            'command': 'GitLab',
            'tool_name': 'discussion_list',
            'arguments': args,
        }
    )

    assert unified.event_name == AiHookEventType.MCP_EXECUTION
    assert unified.mcp_server_name == 'GitLab'
    assert unified.mcp_tool_name == 'discussion_list'
    assert unified.mcp_arguments == args


def test_parse_alternative_field_names() -> None:
    """Cursor's payload has alternative names for some fields."""
    fr = Cursor().parse_hook_payload({'hook_event_name': 'beforeReadFile', 'path': '/alt/path.txt'})
    assert fr.file_path == '/alt/path.txt'

    mcp = Cursor().parse_hook_payload(
        {
            'hook_event_name': 'beforeMCPExecution',
            'tool': 'my_tool',
            'tool_input': {'key': 'value'},
        }
    )
    assert mcp.mcp_tool_name == 'my_tool'
    assert mcp.mcp_arguments == {'key': 'value'}


def test_parse_unknown_event_name_falls_through() -> None:
    """Unknown event names pass through as the raw string."""
    unified = Cursor().parse_hook_payload({'hook_event_name': 'unknownEvent'})
    assert unified.event_name == 'unknownEvent'


def test_parse_empty_payload_defaults() -> None:
    unified = Cursor().parse_hook_payload({'hook_event_name': 'beforeSubmitPrompt'})
    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.conversation_id is None
    assert unified.prompt == ''
    assert unified.ide_provider == 'cursor'


def test_build_prompt_responses() -> None:
    cursor = Cursor()
    assert cursor.build_hook_response(HookDecision.allow(AiHookEventType.PROMPT)) == {'continue': True}
    assert cursor.build_hook_response(HookDecision.deny(AiHookEventType.PROMPT, 'no!')) == {
        'continue': False,
        'user_message': 'no!',
    }


def test_build_permission_responses() -> None:
    cursor = Cursor()
    assert cursor.build_hook_response(HookDecision.allow(AiHookEventType.FILE_READ)) == {'permission': 'allow'}
    assert cursor.build_hook_response(HookDecision.deny(AiHookEventType.FILE_READ, 'user!', 'agent!')) == {
        'permission': 'deny',
        'user_message': 'user!',
        'agent_message': 'agent!',
    }
    assert cursor.build_hook_response(HookDecision.ask(AiHookEventType.MCP_EXECUTION, 'u', 'a')) == {
        'permission': 'ask',
        'user_message': 'u',
        'agent_message': 'a',
    }


def test_session_payload_carries_cursor_fields() -> None:
    payload = {
        'conversation_id': 'conv-456',
        'user_email': 'cursor-user@example.com',
        'model': 'gpt-4',
        'cursor_version': '0.42.0',
    }
    session = Cursor().build_session_payload(payload)
    assert session.conversation_id == 'conv-456'
    assert session.model == 'gpt-4'
    assert session.ide_user_email == 'cursor-user@example.com'
    assert session.ide_version == '0.42.0'
    assert session.ide_provider == 'cursor'


def test_session_context_loads_mcp_servers(tmp_path: Path) -> None:
    """Cursor reads MCP servers from ~/.cursor/mcp.json."""
    mcp_servers = {'github': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-github']}}
    config_path = tmp_path / 'mcp.json'
    config_path.write_text(json.dumps({'mcpServers': mcp_servers}))

    with patch('cycode.cli.apps.ai_guardrails.ides.cursor._load_cursor_mcp_config') as load:
        load.return_value = {'mcpServers': mcp_servers}
        servers, plugins = Cursor().get_session_context()

    assert servers == mcp_servers
    assert plugins == {}


def test_session_context_no_config_returns_empty() -> None:
    with patch('cycode.cli.apps.ai_guardrails.ides.cursor._load_cursor_mcp_config', return_value=None):
        servers, plugins = Cursor().get_session_context()
    assert servers == {}
    assert plugins == {}
