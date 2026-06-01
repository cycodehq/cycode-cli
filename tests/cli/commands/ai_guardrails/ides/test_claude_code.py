"""Claude Code IDE integration tests."""

import json
from pathlib import Path
from unittest.mock import patch

from pyfakefs.fake_filesystem import FakeFilesystem
from pytest_mock import MockerFixture

from cycode.cli.apps.ai_guardrails.ides.base import HookDecision
from cycode.cli.apps.ai_guardrails.ides.claude_code import (
    ClaudeCode,
    _email_from_config,
    _read_claude_plugin,
    load_claude_config,
)
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType


def test_matches_payload_only_claude_events() -> None:
    claude = ClaudeCode()
    assert claude.matches_payload({'hook_event_name': 'UserPromptSubmit'}) is True
    assert claude.matches_payload({'hook_event_name': 'PreToolUse'}) is True
    assert claude.matches_payload({'hook_event_name': 'beforeSubmitPrompt'}) is False
    assert claude.matches_payload({'hook_event_name': 'beforeReadFile'}) is False


def test_parse_prompt_payload() -> None:
    unified = ClaudeCode().parse_hook_payload(
        {
            'hook_event_name': 'UserPromptSubmit',
            'session_id': 'session-123',
            'prompt': 'Test prompt',
        }
    )
    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.conversation_id == 'session-123'
    assert unified.ide_provider == 'claude-code'
    assert unified.prompt == 'Test prompt'


def test_parse_file_read_payload() -> None:
    unified = ClaudeCode().parse_hook_payload(
        {
            'hook_event_name': 'PreToolUse',
            'session_id': 'session-456',
            'tool_name': 'Read',
            'tool_input': {'file_path': '/path/to/secret.env'},
        }
    )
    assert unified.event_name == AiHookEventType.FILE_READ
    assert unified.file_path == '/path/to/secret.env'
    assert unified.mcp_tool_name is None


def test_parse_mcp_execution_payload() -> None:
    args = {'resource_type': 'merge_request', 'parent_id': 'org/repo', 'resource_id': '4'}
    unified = ClaudeCode().parse_hook_payload(
        {
            'hook_event_name': 'PreToolUse',
            'tool_name': 'mcp__gitlab__discussion_list',
            'tool_input': args,
        }
    )

    assert unified.event_name == AiHookEventType.MCP_EXECUTION
    assert unified.mcp_server_name == 'gitlab'
    assert unified.mcp_tool_name == 'discussion_list'
    assert unified.mcp_arguments == args


def test_parse_empty_payload_defaults() -> None:
    unified = ClaudeCode().parse_hook_payload({'hook_event_name': 'UserPromptSubmit'})
    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.conversation_id is None
    assert unified.prompt == ''
    assert unified.ide_provider == 'claude-code'


def test_build_prompt_responses() -> None:
    claude = ClaudeCode()
    assert claude.build_hook_response(HookDecision.allow(AiHookEventType.PROMPT)) == {}
    assert claude.build_hook_response(HookDecision.deny(AiHookEventType.PROMPT, 'no!')) == {
        'decision': 'block',
        'reason': 'no!',
    }


def test_build_permission_responses() -> None:
    claude = ClaudeCode()
    allow = claude.build_hook_response(HookDecision.allow(AiHookEventType.FILE_READ))
    assert allow == {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'allow'}}

    deny = claude.build_hook_response(HookDecision.deny(AiHookEventType.FILE_READ, 'user!', 'agent!'))
    assert deny == {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': 'deny',
            'permissionDecisionReason': 'user!',
        }
    }

    ask = claude.build_hook_response(HookDecision.ask(AiHookEventType.MCP_EXECUTION, 'u'))
    assert ask == {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': 'ask',
            'permissionDecisionReason': 'u',
        }
    }


# Transcript extraction


def test_extract_from_transcript(mocker: MockerFixture) -> None:
    """version, model, generation_id from a Claude Code transcript JSONL."""
    transcript_content = (
        b'{"type":"user","version":"2.1.20","uuid":"user-uuid-1","message":{"role":"user","content":"hello"}}\n'
        b'{"type":"assistant","message":{"model":"claude-opus-4-5-20251101","role":"assistant",'
        b'"content":[{"type":"text","text":"Hi!"}]},"uuid":"assistant-uuid-1"}\n'
        b'{"type":"user","version":"2.1.20","uuid":"user-uuid-2","message":{"role":"user","content":"test prompt"}}\n'
    )
    mock_path = mocker.patch('cycode.cli.apps.ai_guardrails.ides.claude_code.Path')
    mock_path.return_value.exists.return_value = True
    mock_path.return_value.open.return_value.__enter__.return_value.seek = mocker.Mock()
    mock_path.return_value.open.return_value.__enter__.return_value.tell.return_value = len(transcript_content)
    mock_path.return_value.open.return_value.__enter__.return_value.read.return_value = transcript_content

    unified = ClaudeCode().parse_hook_payload(
        {
            'hook_event_name': 'UserPromptSubmit',
            'session_id': 'session-123',
            'prompt': 'test prompt',
            'transcript_path': '/mock/transcript.jsonl',
        }
    )

    assert unified.ide_version == '2.1.20'
    assert unified.model == 'claude-opus-4-5-20251101'
    assert unified.generation_id == 'user-uuid-2'


def test_missing_transcript_does_not_break_parsing(mocker: MockerFixture) -> None:
    mock_path = mocker.patch('cycode.cli.apps.ai_guardrails.ides.claude_code.Path')
    mock_path.return_value.exists.return_value = False

    unified = ClaudeCode().parse_hook_payload(
        {
            'hook_event_name': 'UserPromptSubmit',
            'session_id': 'session-123',
            'prompt': 'test',
            'transcript_path': '/nonexistent/path/transcript.jsonl',
        }
    )

    assert unified.ide_version is None
    assert unified.model is None
    assert unified.generation_id is None
    assert unified.conversation_id == 'session-123'
    assert unified.prompt == 'test'


def test_absent_transcript_path() -> None:
    unified = ClaudeCode().parse_hook_payload(
        {
            'hook_event_name': 'UserPromptSubmit',
            'session_id': 'session-123',
            'prompt': 'test',
        }
    )
    assert unified.ide_version is None
    assert unified.model is None
    assert unified.generation_id is None


# Email extraction from ~/.claude.json


def test_email_from_config(mocker: MockerFixture) -> None:
    mocker.patch(
        'cycode.cli.apps.ai_guardrails.ides.claude_code.load_claude_config',
        return_value={'oauthAccount': {'emailAddress': 'user@example.com'}},
    )
    unified = ClaudeCode().parse_hook_payload(
        {
            'hook_event_name': 'UserPromptSubmit',
            'session_id': 'session-123',
        }
    )
    assert unified.ide_user_email == 'user@example.com'


def test_email_none_when_config_missing(mocker: MockerFixture) -> None:
    mocker.patch(
        'cycode.cli.apps.ai_guardrails.ides.claude_code.load_claude_config',
        return_value=None,
    )
    unified = ClaudeCode().parse_hook_payload(
        {
            'hook_event_name': 'UserPromptSubmit',
            'session_id': 'session-123',
        }
    )
    assert unified.ide_user_email is None


def test_email_none_when_no_oauth(mocker: MockerFixture) -> None:
    mocker.patch(
        'cycode.cli.apps.ai_guardrails.ides.claude_code.load_claude_config',
        return_value={'someOtherKey': 'value'},
    )
    unified = ClaudeCode().parse_hook_payload(
        {
            'hook_event_name': 'UserPromptSubmit',
            'session_id': 'session-123',
        }
    )
    assert unified.ide_user_email is None


# _read_claude_plugin


def test_read_claude_plugin_includes_mcp_config_file(tmp_path: Path) -> None:
    mcp_content = {'mcpServers': {'aspire': {'command': 'aspire', 'args': ['mcp', 'start']}}}
    (tmp_path / '.mcp.json').write_text(json.dumps(mcp_content))

    entry, servers = _read_claude_plugin(tmp_path)

    assert 'mcp_config_file' in entry
    assert json.loads(entry['mcp_config_file']) == mcp_content
    assert servers == mcp_content['mcpServers']


def test_read_claude_plugin_no_mcp_config_file_when_no_servers(tmp_path: Path) -> None:
    (tmp_path / '.mcp.json').write_text(json.dumps({'mcpServers': {}}))

    entry, servers = _read_claude_plugin(tmp_path)

    assert 'mcp_config_file' not in entry
    assert servers == {}


def test_read_claude_plugin_no_mcp_config_file_when_missing(tmp_path: Path) -> None:
    entry, servers = _read_claude_plugin(tmp_path)

    assert 'mcp_config_file' not in entry
    assert servers == {}


# Session context


def test_session_context_no_config() -> None:
    with (
        patch('cycode.cli.apps.ai_guardrails.ides.claude_code.load_claude_config', return_value=None),
        patch('cycode.cli.apps.ai_guardrails.ides.claude_code.load_claude_settings', return_value=None),
    ):
        servers, plugins = ClaudeCode().get_session_context()
    assert servers == {}
    assert plugins == {}


# Claude config parsing (load_claude_config + _email_from_config)


def test_load_claude_config_valid(fs: FakeFilesystem) -> None:
    config = {'oauthAccount': {'emailAddress': 'user@example.com'}}
    config_path = Path.home() / '.claude.json'
    fs.create_file(config_path, contents=json.dumps(config))

    assert load_claude_config(config_path) == config


def test_load_claude_config_missing_file(fs: FakeFilesystem) -> None:
    fs.create_dir(Path.home())
    assert load_claude_config(Path.home() / '.claude.json') is None


def test_load_claude_config_corrupt_file(fs: FakeFilesystem) -> None:
    config_path = Path.home() / '.claude.json'
    fs.create_file(config_path, contents='not valid json {{{')

    assert load_claude_config(config_path) is None


def test_email_from_config_present() -> None:
    assert _email_from_config({'oauthAccount': {'emailAddress': 'user@example.com'}}) == 'user@example.com'


def test_email_from_config_missing_oauth_account() -> None:
    assert _email_from_config({'someOtherKey': 'value'}) is None


def test_email_from_config_missing_email_address() -> None:
    assert _email_from_config({'oauthAccount': {'someOtherField': 'value'}}) is None
