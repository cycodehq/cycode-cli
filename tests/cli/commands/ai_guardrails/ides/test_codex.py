"""Codex CLI IDE integration tests."""

import base64
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.ides.base import HookDecision
from cycode.cli.apps.ai_guardrails.ides.codex import (
    Codex,
    _codex_home,
    _email_from_auth,
    _enable_codex_hooks_feature,
    _load_codex_config,
    _read_codex_plugin,
)
from cycode.cli.apps.ai_guardrails.scan.prompt_images import PromptImage
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - py<3.11 fallback
    import tomli as tomllib


# --- payload parsing ---------------------------------------------------------


def test_matches_payload_only_codex_events() -> None:
    codex = Codex()
    assert codex.matches_payload({'hook_event_name': 'UserPromptSubmit'}) is True
    assert codex.matches_payload({'hook_event_name': 'PreToolUse'}) is True
    assert codex.matches_payload({'hook_event_name': 'beforeSubmitPrompt'}) is False
    assert codex.matches_payload({'hook_event_name': 'SessionStart'}) is False


def test_parse_prompt_payload() -> None:
    unified = Codex().parse_hook_payload(
        {
            'hook_event_name': 'UserPromptSubmit',
            'session_id': 'session-123',
            'turn_id': 'turn-456',
            'model': 'gpt-5-codex',
            'prompt': 'Test prompt',
        }
    )
    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.conversation_id == 'session-123'
    assert unified.generation_id == 'turn-456'
    assert unified.model == 'gpt-5-codex'
    assert unified.ide_provider == 'codex'
    assert unified.prompt == 'Test prompt'


def test_parse_mcp_execution_payload() -> None:
    args = {'resource_type': 'merge_request', 'resource_id': '4'}
    unified = Codex().parse_hook_payload(
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


_CODEX_HOME = '/dummy/codex-home'


def _parse_mcp(tool_name: str) -> tuple:
    unified = Codex().parse_hook_payload({'hook_event_name': 'PreToolUse', 'tool_name': tool_name})
    return unified.mcp_server_name, unified.mcp_tool_name


@pytest.fixture
def codex_servers(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> FakeFilesystem:
    monkeypatch.setenv('CODEX_HOME', _CODEX_HOME)
    fs.create_file(
        f'{_CODEX_HOME}/config.toml',
        contents=(
            '[mcp_servers.my-server]\ncommand = "a"\n'
            '[mcp_servers."docs.example.com"]\ncommand = "b"\n'
            '[mcp_servers.a__b]\ncommand = "c"\n'
            '[mcp_servers.a]\ncommand = "d"\n'
            '[plugins."demo@market"]\nenabled = true\n'
        ),
    )
    plugin_dir = Path(f'{_CODEX_HOME}/plugins/cache/market/demo/abc123')
    fs.create_file(plugin_dir / '.codex-plugin' / 'plugin.json', contents=json.dumps({'mcpServers': '.mcp.json'}))
    fs.create_file(plugin_dir / '.mcp.json', contents=json.dumps({'mcpServers': {'plugin-srv': {'command': 'e'}}}))
    return fs


@pytest.mark.parametrize(
    ('tool_name', 'expected'),
    [
        ('mcp__my_server__list', ('my-server', 'list')),
        ('mcp__docs_example_com__search', ('docs.example.com', 'search')),
        ('mcp__plugin_srv__run', ('plugin-srv', 'run')),
        ('mcp__my_server_0123456789ab__list', ('my-server', 'list')),
        ('mcp__a__b__tool', ('a__b', 'tool')),
        ('mcp__a__tool', ('a', 'tool')),
        ('mcp__unknown__tool', ('unknown', 'tool')),
    ],
)
def test_parse_mcp_resolves_codex_server_name(codex_servers: FakeFilesystem, tool_name: str, expected: tuple) -> None:
    assert _parse_mcp(tool_name) == expected


def test_parse_non_mcp_event_reads_no_codex_config() -> None:
    with patch('cycode.cli.apps.ai_guardrails.ides.codex._load_codex_config') as load_config:
        Codex().parse_hook_payload({'hook_event_name': 'UserPromptSubmit', 'prompt': 'hi'})
    load_config.assert_not_called()


def test_parse_unknown_event_falls_through() -> None:
    unified = Codex().parse_hook_payload({'hook_event_name': 'Stop'})
    assert unified.event_name == 'Stop'


def test_parse_empty_payload_defaults() -> None:
    unified = Codex().parse_hook_payload({'hook_event_name': 'UserPromptSubmit'})
    assert unified.event_name == AiHookEventType.PROMPT
    assert unified.prompt == ''
    assert unified.ide_provider == 'codex'


# --- response building -------------------------------------------------------


def test_build_prompt_responses() -> None:
    codex = Codex()
    assert codex.build_hook_response(HookDecision.allow(AiHookEventType.PROMPT)) == {}
    assert codex.build_hook_response(HookDecision.deny(AiHookEventType.PROMPT, 'no!')) == {
        'decision': 'block',
        'reason': 'no!',
    }


def test_build_mcp_execution_allow_and_deny() -> None:
    codex = Codex()
    allow = codex.build_hook_response(HookDecision.allow(AiHookEventType.MCP_EXECUTION))
    # Explicit permissionDecision "allow" is rejected by older Codex runtimes.
    assert allow == {}

    deny = codex.build_hook_response(HookDecision.deny(AiHookEventType.MCP_EXECUTION, 'secret in args!', 'agent!'))
    assert deny == {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': 'deny',
            'permissionDecisionReason': 'secret in args!\nagent!',
        }
    }


def test_build_mcp_execution_ask() -> None:
    ask = Codex().build_hook_response(HookDecision.ask(AiHookEventType.MCP_EXECUTION, 'maybe?'))
    assert ask == {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': 'ask',
            'permissionDecisionReason': 'maybe?',
        }
    }


# --- settings paths ----------------------------------------------------------


def test_settings_path_user_scope() -> None:
    path = Codex().settings_path('user')
    assert path.name == 'hooks.json'
    assert path.parent.name == '.codex'


def test_settings_path_repo_scope(fs: FakeFilesystem) -> None:
    repo = Path('/my-repo')
    fs.create_dir(repo)
    path = Codex().settings_path('repo', repo)
    assert path == repo / '.codex' / 'hooks.json'


def test_settings_path_honors_codex_home_env(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    override = '/custom/codex/home'
    fs.create_dir(override)
    monkeypatch.setenv('CODEX_HOME', override)
    assert _codex_home() == Path(override)
    assert Codex().settings_path('user') == Path(override) / 'hooks.json'


# --- hooks config rendering --------------------------------------------------


def test_render_hooks_session_start_matches_all_sources() -> None:
    """SessionStart must fire on every source (a forked session reports 'resume',
    so no matcher is set -> match-all)."""
    rendered = Codex().render_hooks_config()
    assert 'matcher' not in rendered['hooks']['SessionStart'][0]
    assert '--ide codex' in rendered['hooks']['SessionStart'][0]['hooks'][0]['command']


def test_render_hooks_never_emits_async_toml_flags() -> None:
    """Codex's TOML `async: true` / `timeout` flags are unimplemented; we must not emit them."""
    rendered = Codex().render_hooks_config()
    for entry in rendered['hooks']['PreToolUse']:
        for hook in entry['hooks']:
            assert 'async' not in hook
            assert 'timeout' not in hook


def test_render_hooks_commands_always_plain_sync() -> None:
    """Hooks are always installed plain sync: warn-vs-block synchronicity is
    decided at scan time by the CLI itself (self-detach)."""
    rendered = Codex().render_hooks_config()
    prompt_cmd = rendered['hooks']['UserPromptSubmit'][0]['hooks'][0]['command']
    pretool_cmd = rendered['hooks']['PreToolUse'][0]['hooks'][0]['command']
    session_cmd = rendered['hooks']['SessionStart'][0]['hooks'][0]['command']
    assert '&' not in prompt_cmd
    assert '&' not in pretool_cmd
    assert '&' not in session_cmd


def test_render_hooks_pretooluse_matchers_are_mcp_only() -> None:
    matchers = [e['matcher'] for e in Codex().render_hooks_config()['hooks']['PreToolUse']]
    assert matchers == ['mcp__.*']


# --- post_install: TOML feature flag ----------------------------------------


def test_post_install_creates_config_toml(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    home = '/codex-home'
    fs.create_dir(home)
    monkeypatch.setenv('CODEX_HOME', home)

    success, message = Codex().post_install('user')
    assert success is True
    config_path = Path(home) / 'config.toml'
    assert config_path.exists()
    assert 'config.toml' in message

    with config_path.open('rb') as f:
        config = tomllib.load(f)
    assert config['features']['hooks'] is True


def test_post_install_preserves_existing_keys(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    home = '/codex-home'
    fs.create_dir(home)
    monkeypatch.setenv('CODEX_HOME', home)
    config_path = Path(home) / 'config.toml'
    # Pre-existing settings the user cares about
    config_path.write_text('model = "gpt-5-codex"\n\n[features]\nother = true\n')

    success, _ = Codex().post_install('user')
    assert success is True

    with config_path.open('rb') as f:
        config = tomllib.load(f)
    assert config['model'] == 'gpt-5-codex'
    assert config['features']['other'] is True
    assert config['features']['hooks'] is True


def test_post_install_repo_scope_writes_to_repo_dir(fs: FakeFilesystem) -> None:
    repo = Path('/my-repo')
    fs.create_dir(repo)
    success, _ = Codex().post_install('repo', repo)
    assert success is True
    assert (repo / '.codex' / 'config.toml').exists()


def test_enable_codex_hooks_feature_fails_on_corrupt_toml(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    home = '/codex-home'
    fs.create_dir(home)
    monkeypatch.setenv('CODEX_HOME', home)
    (Path(home) / 'config.toml').write_text('this is = not [ valid] toml = ')

    success, message = _enable_codex_hooks_feature('user')
    assert success is False
    assert 'Failed to parse' in message


# --- TOML config loading -----------------------------------------------------


def test_load_codex_config_valid(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    home = '/codex-home'
    fs.create_dir(home)
    monkeypatch.setenv('CODEX_HOME', home)
    (Path(home) / 'config.toml').write_text('model = "gpt-5-codex"\n[mcp_servers.linear]\ncommand = "linear-mcp"\n')

    config = _load_codex_config()
    assert config is not None
    assert config['model'] == 'gpt-5-codex'
    assert config['mcp_servers']['linear']['command'] == 'linear-mcp'


def test_load_codex_config_missing_file(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    home = '/codex-home'
    fs.create_dir(home)
    monkeypatch.setenv('CODEX_HOME', home)
    assert _load_codex_config() is None


def test_load_codex_config_invalid_toml(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    home = '/codex-home'
    fs.create_dir(home)
    monkeypatch.setenv('CODEX_HOME', home)
    (Path(home) / 'config.toml').write_text('this is = not [ valid] toml = ')
    assert _load_codex_config() is None


# --- JWT email extraction ----------------------------------------------------


def _make_jwt(claims: dict) -> str:
    """Build a JWT-shaped token with the given claims (signature ignored)."""
    header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b'=').decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
    signature = base64.urlsafe_b64encode(b'signature-not-verified').rstrip(b'=').decode()
    return f'{header}.{payload}.{signature}'


def test_email_from_auth_returns_email(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    home = '/codex-home'
    fs.create_dir(home)
    monkeypatch.setenv('CODEX_HOME', home)
    token = _make_jwt({'email': 'codex-user@example.com'})
    (Path(home) / 'auth.json').write_text(json.dumps({'tokens': {'id_token': token}}))

    assert _email_from_auth() == 'codex-user@example.com'


def test_email_from_auth_missing_file(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    home = '/codex-home'
    fs.create_dir(home)
    monkeypatch.setenv('CODEX_HOME', home)
    assert _email_from_auth() is None


def test_email_from_auth_no_id_token(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    home = '/codex-home'
    fs.create_dir(home)
    monkeypatch.setenv('CODEX_HOME', home)
    (Path(home) / 'auth.json').write_text(json.dumps({'tokens': {}}))
    assert _email_from_auth() is None


def test_email_from_auth_malformed_token(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    home = '/codex-home'
    fs.create_dir(home)
    monkeypatch.setenv('CODEX_HOME', home)
    (Path(home) / 'auth.json').write_text(json.dumps({'tokens': {'id_token': 'not.a.jwt-with-bad-payload!!'}}))
    assert _email_from_auth() is None


# --- session context --------------------------------------------------------


def test_session_context_reads_mcp_servers() -> None:
    mcp = {'linear': {'command': 'linear-mcp'}, 'github': {'command': 'gh-mcp'}}
    with patch(
        'cycode.cli.apps.ai_guardrails.ides.codex._load_codex_config',
        return_value={'mcp_servers': mcp},
    ):
        global_config_files, plugins = Codex().get_session_context()
    assert len(global_config_files) == 1
    assert global_config_files[0]['path'].endswith('config.toml')
    assert global_config_files[0]['content'] == json.dumps({'mcpServers': mcp})
    assert plugins == {}


def test_session_context_no_config() -> None:
    with patch('cycode.cli.apps.ai_guardrails.ides.codex._load_codex_config', return_value=None):
        global_config_files, plugins = Codex().get_session_context()
    assert global_config_files == []
    assert plugins == {}


def _write_codex_plugin(plugin_dir: Path, mcp_doc: dict) -> None:
    """Lay out a Codex plugin: manifest referencing .mcp.json + the MCP file itself."""
    (plugin_dir / '.codex-plugin').mkdir(parents=True, exist_ok=True)
    (plugin_dir / '.codex-plugin' / 'plugin.json').write_text(json.dumps({'name': 'demo', 'mcpServers': '.mcp.json'}))
    (plugin_dir / '.mcp.json').write_text(json.dumps(mcp_doc))


def test_read_codex_plugin_includes_mcp_config_file(tmp_path: Path) -> None:
    mcp_content = {'mcpServers': {'dummy-server': {'command': 'dummy-command', 'args': ['serve']}}}
    _write_codex_plugin(tmp_path, mcp_content)

    entry, servers = _read_codex_plugin(tmp_path)

    assert json.loads(entry['mcp_config_file']) == mcp_content
    assert entry['mcp_config_file_path'] == str(tmp_path / '.mcp.json')
    assert servers == mcp_content['mcpServers']


def test_read_codex_plugin_mcp_config_file_bare_map(tmp_path: Path) -> None:
    # Codex MCP files may be a bare {name: cfg} map with no mcpServers wrapper; the serialized
    # session-context content is normalized to the canonical wrapped shape.
    mcp_content = {'dummy-server': {'command': 'dummy-command'}}
    _write_codex_plugin(tmp_path, mcp_content)

    entry, servers = _read_codex_plugin(tmp_path)

    assert json.loads(entry['mcp_config_file']) == {'mcpServers': mcp_content}
    assert servers == mcp_content


def test_read_codex_plugin_no_mcp_config_file_when_no_servers(tmp_path: Path) -> None:
    _write_codex_plugin(tmp_path, {'mcpServers': {}})

    entry, servers = _read_codex_plugin(tmp_path)

    assert 'mcp_config_file' not in entry
    assert servers == {}


def test_read_codex_plugin_no_mcp_config_file_when_no_manifest(tmp_path: Path) -> None:
    entry, servers = _read_codex_plugin(tmp_path)

    assert 'mcp_config_file' not in entry
    assert servers == {}


def test_read_codex_plugin_collects_plugin_skills(fs: FakeFilesystem) -> None:
    """Plugin skills are a property of the plugin format, so Codex plugins carry them too."""
    plugin_dir = Path('/dummy/codex-marketplace/dummy-plugin')
    fs.create_file(
        plugin_dir / '.codex-plugin' / 'plugin.json',
        contents=json.dumps({'name': 'dummy-plugin', 'version': '3.0.0'}),
    )
    skill_file = plugin_dir / 'skills' / 'codex-skill' / 'SKILL.md'
    fs.create_file(skill_file, contents='---\nname: codex-skill\n---\nBody.\n')

    entry, _ = _read_codex_plugin(plugin_dir)

    assert [s['path'] for s in entry['skill_files']] == [str(skill_file)]


# skills


def test_get_skills_reads_user_scope_skills(fs: FakeFilesystem) -> None:
    body = '---\nname: dummy-skill\ndescription: Dummy.\n---\n\nDo it.\n'
    skill_file = Path.home() / '.codex' / 'skills' / 'dummy-skill' / 'SKILL.md'
    fs.create_file(skill_file, contents=body)

    skills = Codex().get_skills()

    assert skills == [{'path': str(skill_file), 'content': body}]


def test_get_skills_no_skills_dir_returns_empty(fs: FakeFilesystem) -> None:
    assert Codex().get_skills() == []


# --- prompt images ----------------------------------------------------------------


def _png(marker: bytes) -> bytes:
    return b'\x89PNG\r\n\x1a\n' + marker


def _paste(fs: FakeFilesystem, name: str, modified_at: float) -> str:
    """An image the terminal UI saved from the clipboard."""
    path = Path(tempfile.gettempdir()) / f'codex-clipboard-{name}.png'
    fs.create_file(path, contents=_png(name.encode()))
    os.utime(path, (modified_at, modified_at))
    return str(path)


def _at(seconds: float) -> str:
    """A transcript timestamp, as Codex writes it."""
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def _message(seconds: float, role: str, text: str) -> dict:
    content = [{'type': 'input_text', 'text': text}]
    return {
        'timestamp': _at(seconds),
        'type': 'response_item',
        'payload': {'type': 'message', 'role': role, 'content': content},
    }


def _transcript(fs: FakeFilesystem, started: float, *prompts: tuple[float, bool], extra: tuple[str, ...] = ()) -> str:
    """A session transcript as Codex writes it: the session's start and context, then a turn per prompt.

    Each prompt is (submitted at, whether its hook let it through). Codex records a prompt as a user message only when
    it went through; a blocked one leaves only the turn's bookkeeping.
    """
    path = '/Users/user/.codex/sessions/2026/11/17/rollout-session-1.jsonl'
    lines = [
        {'timestamp': _at(started), 'type': 'session_meta', 'payload': {'id': 'session-1'}},
        _message(started, 'developer', 'instructions'),
        # The session's context, written before the first turn: not a prompt
        _message(started, 'user', '<environment_context>'),
    ]
    for submitted_at, went_through in prompts:
        lines.append({'timestamp': _at(submitted_at), 'type': 'event_msg', 'payload': {'type': 'task_started'}})
        lines.append({'timestamp': _at(submitted_at), 'type': 'turn_context', 'payload': {}})
        if went_through:
            lines.append(_message(submitted_at, 'user', '<image name=[Image #1] path="/tmp/codex-clipboard-x.png">'))
        lines.append({'timestamp': _at(submitted_at + 1), 'type': 'event_msg', 'payload': {'type': 'task_complete'}})
    text = '\n'.join([*(json.dumps(line) for line in lines), *extra]) + '\n'
    fs.create_file(path, contents=text)
    return path


def _prompt_payload(prompt: str, transcript_path: str | None = None) -> dict:
    return {
        'hook_event_name': 'UserPromptSubmit',
        'session_id': 'session-1',
        'turn_id': 'turn-1',
        'transcript_path': transcript_path,
        'cwd': '/Users/user/project',
        'prompt': prompt,
    }


def _paths(images: list[PromptImage]) -> list[str]:
    return [image.path for image in images]


def test_collect_prompt_images_takes_the_newest_paste_per_chip(fs: FakeFilesystem) -> None:
    now = time.time()
    _paste(fs, 'Old111', now - 300)
    middle = _paste(fs, 'Mid222', now - 60)
    newest = _paste(fs, 'New333', now - 5)
    transcript = _transcript(fs, now - 2)

    images = Codex().collect_prompt_images(_prompt_payload('[Image #1] [Image #2] what changed?', transcript))

    # Oldest first, the order they were pasted in
    assert _paths(images) == [middle, newest]


def test_collect_prompt_images_takes_only_pastes_since_the_last_prompt_that_went_through(fs: FakeFilesystem) -> None:
    now = time.time()
    _paste(fs, 'Before11', now - 200)
    after = _paste(fs, 'After222', now - 30)
    transcript = _transcript(fs, now - 300, (now - 190, True))

    payload = _prompt_payload('[Image #1] [Image #2]', transcript)

    assert _paths(Codex().collect_prompt_images(payload)) == [after]


def test_collect_prompt_images_finds_a_blocked_prompts_paste_again(fs: FakeFilesystem) -> None:
    now = time.time()
    pasted = _paste(fs, 'Blocked1', now - 110)
    # A blocked prompt isn't recorded, so its paste is found again when it is sent again
    transcript = _transcript(fs, now - 300, (now - 250, True), (now - 100, False))

    assert _paths(Codex().collect_prompt_images(_prompt_payload('[Image #1] again', transcript))) == [pasted]


def test_collect_prompt_images_takes_no_earlier_paste_for_a_dragged_image(fs: FakeFilesystem) -> None:
    now = time.time()
    # Left by a blocked prompt, or by another session, before this session's last prompt went through
    _paste(fs, 'Blocked1', now - 200)
    transcript = _transcript(fs, now - 300, (now - 190, False), (now - 60, True))

    payload = _prompt_payload('[Image #1] what is it', transcript)

    assert Codex().collect_prompt_images(payload) == []


def test_collect_prompt_images_first_prompt_looks_back_ten_minutes_from_the_session_start(fs: FakeFilesystem) -> None:
    now = time.time()
    _paste(fs, 'TooOld11', now - 700)
    recent = _paste(fs, 'Recent22', now - 400)
    # Codex starts the transcript when the first prompt is submitted, after its pastes
    transcript = _transcript(fs, now - 5)

    payload = _prompt_payload('[Image #1] [Image #2]', transcript)

    assert _paths(Codex().collect_prompt_images(payload)) == [recent]


def test_collect_prompt_images_skips_a_resumed_sessions_context(fs: FakeFilesystem) -> None:
    now = time.time()
    pasted = _paste(fs, 'Recent11', now - 30)
    # A resumed session starts again with its context, which is no prompt that went through
    resumed = (
        json.dumps({'timestamp': _at(now - 20), 'type': 'session_meta', 'payload': {'id': 'session-1'}}),
        json.dumps(_message(now - 20, 'user', '<environment_context>')),
    )
    transcript = _transcript(fs, now - 300, (now - 250, True), extra=resumed)

    assert _paths(Codex().collect_prompt_images(_prompt_payload('[Image #1]', transcript))) == [pasted]


def test_collect_prompt_images_takes_no_paste_without_a_chip(fs: FakeFilesystem) -> None:
    now = time.time()
    _paste(fs, 'Recent11', now - 5)

    assert Codex().collect_prompt_images(_prompt_payload('no image here', _transcript(fs, now - 2))) == []


def test_collect_prompt_images_counts_a_repeated_chip_once(fs: FakeFilesystem) -> None:
    now = time.time()
    _paste(fs, 'First111', now - 60)
    newest = _paste(fs, 'Second22', now - 5)

    payload = _prompt_payload('compare [Image #1] with itself: [Image #1]', _transcript(fs, now - 2))

    assert _paths(Codex().collect_prompt_images(payload)) == [newest]


def test_collect_prompt_images_ignores_pastes_older_than_an_hour(fs: FakeFilesystem) -> None:
    now = time.time()
    _paste(fs, 'Stale111', now - 2 * 60 * 60)
    transcript = _transcript(fs, now - 4 * 60 * 60, (now - 3 * 60 * 60, True))

    assert Codex().collect_prompt_images(_prompt_payload('[Image #1]', transcript)) == []


@pytest.mark.parametrize('transcript_path', [None, ''])
def test_collect_prompt_images_takes_no_paste_without_a_transcript(
    fs: FakeFilesystem, transcript_path: str | None
) -> None:
    _paste(fs, 'Recent11', time.time() - 5)
    # The prompt Codex sends to title a new thread has no transcript and quotes the user's prompt, chips included
    title_prompt = 'Generate a concise, single-line task title.\n\nUser prompt:\nwhat does it say? [Image #1]'

    assert Codex().collect_prompt_images(_prompt_payload(title_prompt, transcript_path)) == []


@pytest.mark.parametrize('make_transcript', ['missing', 'directory'])
def test_collect_prompt_images_looks_back_ten_minutes_without_a_readable_transcript(
    fs: FakeFilesystem, make_transcript: str
) -> None:
    now = time.time()
    _paste(fs, 'TooOld11', now - 700)
    pasted = _paste(fs, 'Recent11', now - 5)
    path = '/Users/user/.codex/sessions/2026/11/17/rollout-new.jsonl'
    if make_transcript == 'directory':
        fs.create_dir(path)

    payload = _prompt_payload('[Image #1] [Image #2]', path)

    assert _paths(Codex().collect_prompt_images(payload)) == [pasted]


def test_collect_prompt_images_skips_transcript_lines_it_cannot_read(fs: FakeFilesystem) -> None:
    now = time.time()
    _paste(fs, 'Before11', now - 250)
    after = _paste(fs, 'After222', now - 100)
    odd_lines = (
        'not json, but "user"',
        '["user"]',
        json.dumps({'type': 'response_item', 'payload': {'role': 'user'}}),
        json.dumps({'timestamp': 'yesterday', 'type': 'response_item', 'payload': {'role': 'user'}}),
        json.dumps({'timestamp': _at(now - 50), 'type': 'response_item', 'payload': 'user'}),
        # Not a message line, though its payload names the user
        json.dumps(
            {'timestamp': _at(now - 40), 'type': 'event_msg', 'payload': {'type': 'item_completed', 'role': 'user'}}
        ),
    )
    transcript = _transcript(fs, now - 300, (now - 200, True), extra=odd_lines)

    payload = _prompt_payload('[Image #1] [Image #2]', transcript)

    assert _paths(Codex().collect_prompt_images(payload)) == [after]


def test_collect_prompt_images_finds_mentions_against_cwd(fs: FakeFilesystem) -> None:
    shot = Path('/Users/user/project/docs/shot.png')
    fs.create_file(shot, contents=_png(b'shot'))

    images = Codex().collect_prompt_images(_prompt_payload('explain @docs/shot.png', _transcript(fs, time.time())))

    assert _paths(images) == [str(shot)]
