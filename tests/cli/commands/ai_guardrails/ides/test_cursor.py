"""Cursor IDE integration tests (payload parsing, response building, MCP context)."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem
from pytest_mock import MockerFixture

from cycode.cli.apps.ai_guardrails.ides._vscode_utils import vscode_user_data_dir
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


def test_parse_mcp_execution_payload(fs: FakeFilesystem) -> None:
    # No MCP config on disk: the raw command is kept as the server name.
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


def _write_mcp_config(fs: FakeFilesystem, path: Path, servers: dict) -> None:
    fs.create_file(str(path), contents=json.dumps({'mcpServers': servers}))


def _parse_mcp(**fields: Any) -> Any:
    return Cursor().parse_hook_payload({'hook_event_name': 'beforeMCPExecution', 'tool_name': 't', **fields})


_USER_MCP_CONFIG = Path.home() / '.cursor' / 'mcp.json'


def test_mcp_server_name_resolved_by_url(fs: FakeFilesystem) -> None:
    _write_mcp_config(
        fs,
        _USER_MCP_CONFIG,
        {'notion': {'url': 'https://mcp.notion.com/mcp'}, 'other': {'url': 'https://example.com/mcp'}},
    )

    assert _parse_mcp(url='https://mcp.notion.com/mcp').mcp_server_name == 'notion'


def test_mcp_server_name_resolved_by_command_line(fs: FakeFilesystem) -> None:
    _write_mcp_config(
        fs,
        _USER_MCP_CONFIG,
        {
            'filesystem': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-filesystem']},
            'github': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-github']},
            'local-db': {'command': '/usr/local/bin/db-mcp'},
        },
    )

    assert _parse_mcp(command='npx -y @modelcontextprotocol/server-github').mcp_server_name == 'github'
    assert _parse_mcp(command='/usr/local/bin/db-mcp').mcp_server_name == 'local-db'


def test_mcp_server_name_resolved_by_entry_name(fs: FakeFilesystem) -> None:
    _write_mcp_config(fs, _USER_MCP_CONFIG, {'gitlab': {'command': '/opt/homebrew/bin/gitlab-mcp'}})

    assert _parse_mcp(command='GitLab').mcp_server_name == 'gitlab'


def test_mcp_server_name_prefers_the_project_config(fs: FakeFilesystem) -> None:
    _write_mcp_config(fs, _USER_MCP_CONFIG, {'user-notion': {'url': 'https://mcp.notion.com/mcp'}})
    _write_mcp_config(
        fs, Path('/work/repo/.cursor/mcp.json'), {'project-notion': {'url': 'https://mcp.notion.com/mcp'}}
    )

    unified = _parse_mcp(url='https://mcp.notion.com/mcp', workspace_roots=['/work/repo'])

    assert unified.mcp_server_name == 'project-notion'


def test_mcp_server_name_without_a_matching_entry_falls_back(fs: FakeFilesystem) -> None:
    _write_mcp_config(fs, _USER_MCP_CONFIG, {'notion': {'url': 'https://mcp.notion.com/mcp'}})

    assert _parse_mcp(command='npx some-unknown-server').mcp_server_name == 'npx some-unknown-server'
    assert _parse_mcp(url='https://unknown.example.com/mcp').mcp_server_name is None


def test_mcp_server_name_with_a_corrupt_config_falls_back(fs: FakeFilesystem) -> None:
    fs.create_file(str(_USER_MCP_CONFIG), contents='not json {')

    assert _parse_mcp(command='GitLab').mcp_server_name == 'GitLab'


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
    # beforeReadFile drops agent_message and feeds user_message to the model, so it carries both
    assert cursor.build_hook_response(HookDecision.deny(AiHookEventType.FILE_READ, 'user!', 'agent!')) == {
        'permission': 'deny',
        'user_message': 'user!\nagent!',
        'agent_message': 'user!\nagent!',
    }
    assert cursor.build_hook_response(HookDecision.deny(AiHookEventType.MCP_EXECUTION, 'user!', 'agent!')) == {
        'permission': 'deny',
        'user_message': 'user!',
        # The agent never sees user_message, so it gets the findings too
        'agent_message': 'user!\nagent!',
    }
    assert cursor.build_hook_response(HookDecision.ask(AiHookEventType.MCP_EXECUTION, 'u', 'a')) == {
        'permission': 'ask',
        'user_message': 'u',
        'agent_message': 'u\na',
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


def test_session_context_loads_mcp_servers() -> None:
    """Cursor wraps ~/.cursor/mcp.json into a global config file."""
    mcp_servers = {'github': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-github']}}

    with patch('cycode.cli.apps.ai_guardrails.ides.cursor._load_cursor_mcp_config') as load:
        load.return_value = {'mcpServers': mcp_servers}
        global_config_files, plugins = Cursor().get_session_context()

    assert global_config_files == [
        {
            'path': str(Path.home() / '.cursor' / 'mcp.json'),
            'content': json.dumps({'mcpServers': mcp_servers}),
        }
    ]
    assert plugins == {}


def test_session_context_no_config_returns_empty() -> None:
    with patch('cycode.cli.apps.ai_guardrails.ides.cursor._load_cursor_mcp_config', return_value=None):
        global_config_files, plugins = Cursor().get_session_context()
    assert global_config_files == []
    assert plugins == {}


# skills


def test_get_skills_reads_user_scope_skills(fs: FakeFilesystem) -> None:
    body = '---\nname: dummy-skill\ndescription: Dummy.\n---\n\nDo it.\n'
    skill_file = Path.home() / '.cursor' / 'skills' / 'dummy-skill' / 'SKILL.md'
    fs.create_file(skill_file, contents=body)

    skills = Cursor().get_skills()

    assert skills == [{'path': str(skill_file), 'content': body}]


def test_get_skills_no_skills_dir_returns_empty(fs: FakeFilesystem) -> None:
    assert Cursor().get_skills() == []


# --- prompt images (a real SQLite file, so no fake filesystem) ------------------------

_CONVERSATION_ID = '6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f'
_GENERATION_ID = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d'


def _png(marker: bytes) -> bytes:
    return b'\x89PNG\r\n\x1a\n' + marker


@pytest.fixture
def cursor_user_data(tmp_path: Path, mocker: MockerFixture) -> Path:
    user_data = tmp_path / 'Cursor'
    mocker.patch('cycode.cli.apps.ai_guardrails.ides.cursor.vscode_user_data_dir', return_value=user_data)
    mocker.patch('cycode.cli.apps.ai_guardrails.ides.cursor._PROMPT_RECORD_WAIT_SECONDS', 0)
    return user_data


def _state_db(user_data: Path, bubbles: dict[str, object]) -> Path:
    """Cursor's global state database, holding these bubbles of the conversation (by bubble id)."""
    db_path = user_data / 'User' / 'globalStorage' / 'state.vscdb'
    db_path.parent.mkdir(parents=True)
    with closing(sqlite3.connect(db_path)) as connection, connection:
        connection.execute('CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)')
        connection.executemany(
            'INSERT INTO cursorDiskKV VALUES (?, ?)',
            [(key, value if isinstance(value, str) else json.dumps(value)) for key, value in bubbles.items()],
        )
    return db_path


def _bubble(request_id: str, *image_paths: str) -> dict:
    return {
        'type': 1,
        'requestId': request_id,
        'context': {
            'selectedImages': [{'uuid': f'uuid-{index}', 'path': path} for index, path in enumerate(image_paths)]
        },
    }


def _image(directory: Path, name: str) -> str:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_png(name.encode()))
    return str(path)


def _prompt_payload(**overrides: object) -> dict:
    return {
        'hook_event_name': 'beforeSubmitPrompt',
        'conversation_id': _CONVERSATION_ID,
        'generation_id': _GENERATION_ID,
        'prompt': 'what does this screenshot show?',
        'attachments': [],
        **overrides,
    }


def test_collect_prompt_images_reads_the_prompts_record(cursor_user_data: Path, tmp_path: Path) -> None:
    pasted = _image(cursor_user_data / 'User' / 'workspaceStorage' / 'ws-1' / 'images', 'image-uuid-1.png')
    mentioned = _image(tmp_path / 'project', 'diagram.png')
    earlier = _image(tmp_path / 'project', 'earlier.png')
    other = _image(tmp_path / 'project', 'other.png')
    _state_db(
        cursor_user_data,
        {
            f'bubbleId:{_CONVERSATION_ID}:bubble-1': _bubble('earlier-generation', earlier),
            f'bubbleId:{_CONVERSATION_ID}:bubble-2': _bubble(_GENERATION_ID, pasted, Path(mentioned).as_uri()),
            'bubbleId:another-conversation:bubble-3': _bubble(_GENERATION_ID, other),
            f'composerData:{_CONVERSATION_ID}': {'latestChatGenerationUUID': _GENERATION_ID},
        },
    )

    images = Cursor().collect_prompt_images(_prompt_payload())

    assert [image.path for image in images] == [pasted, mentioned]


def test_collect_prompt_images_finds_nothing_in_a_record_without_images(cursor_user_data: Path) -> None:
    _state_db(cursor_user_data, {f'bubbleId:{_CONVERSATION_ID}:bubble-1': _bubble(_GENERATION_ID)})

    assert Cursor().collect_prompt_images(_prompt_payload()) == []


def test_collect_prompt_images_waits_for_the_record(
    cursor_user_data: Path, tmp_path: Path, mocker: MockerFixture
) -> None:
    pasted = _image(tmp_path / 'images', 'pasted.png')
    db_path = _state_db(cursor_user_data, {})
    mocker.patch('cycode.cli.apps.ai_guardrails.ides.cursor._PROMPT_RECORD_WAIT_SECONDS', 5)

    def save_the_record(_: float) -> None:
        with closing(sqlite3.connect(db_path)) as connection, connection:
            key = f'bubbleId:{_CONVERSATION_ID}:bubble-1'
            connection.execute(
                'INSERT INTO cursorDiskKV VALUES (?, ?)', (key, json.dumps(_bubble(_GENERATION_ID, pasted)))
            )

    sleep = mocker.patch('cycode.cli.apps.ai_guardrails.ides.cursor.time.sleep', side_effect=save_the_record)

    assert [image.path for image in Cursor().collect_prompt_images(_prompt_payload())] == [pasted]
    sleep.assert_called_once()


def test_collect_prompt_images_gives_up_when_the_record_never_comes(cursor_user_data: Path) -> None:
    _state_db(cursor_user_data, {f'bubbleId:{_CONVERSATION_ID}:bubble-1': _bubble('earlier-generation')})

    assert Cursor().collect_prompt_images(_prompt_payload()) == []


@pytest.mark.parametrize(
    'overrides',
    [{'conversation_id': None}, {'generation_id': ''}, {'conversation_id': 7}, {'generation_id': ['x']}],
)
def test_collect_prompt_images_needs_both_ids(cursor_user_data: Path, tmp_path: Path, overrides: dict) -> None:
    pasted = _image(tmp_path / 'images', 'pasted.png')
    _state_db(cursor_user_data, {f'bubbleId:{_CONVERSATION_ID}:bubble-1': _bubble(_GENERATION_ID, pasted)})

    assert Cursor().collect_prompt_images(_prompt_payload(**overrides)) == []


def test_collect_prompt_images_without_a_state_database(cursor_user_data: Path) -> None:
    assert Cursor().collect_prompt_images(_prompt_payload()) == []


def test_collect_prompt_images_skips_an_unreadable_database(cursor_user_data: Path) -> None:
    db_path = cursor_user_data / 'User' / 'globalStorage' / 'state.vscdb'
    db_path.parent.mkdir(parents=True)
    db_path.write_bytes(b'not a database')

    assert Cursor().collect_prompt_images(_prompt_payload()) == []


def test_collect_prompt_images_skips_malformed_records(cursor_user_data: Path, tmp_path: Path) -> None:
    pasted = _image(tmp_path / 'images', 'pasted.png')
    _state_db(
        cursor_user_data,
        {
            f'bubbleId:{_CONVERSATION_ID}:bubble-1': f'not json {_GENERATION_ID}',
            f'bubbleId:{_CONVERSATION_ID}:bubble-2': {
                'requestId': _GENERATION_ID,
                'context': {'selectedImages': [None, {'path': 7}, {'path': ''}, {'path': pasted}]},
            },
        },
    )

    assert [image.path for image in Cursor().collect_prompt_images(_prompt_payload())] == [pasted]


@pytest.mark.parametrize(
    ('system', 'base_parts'),
    [
        ('Darwin', ('Library', 'Application Support')),
        ('Linux', ('.config',)),
        ('Windows', ('AppData', 'Roaming')),
    ],
)
def test_cursor_user_data_dir_per_platform(mocker: MockerFixture, system: str, base_parts: tuple[str, ...]) -> None:
    mocker.patch('cycode.cli.apps.ai_guardrails.ides._vscode_utils.platform.system', return_value=system)

    assert vscode_user_data_dir('Cursor') == Path.home().joinpath(*base_parts, 'Cursor')
