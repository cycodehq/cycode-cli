"""Codex CLI IDE integration tests."""

import base64
import json
import sys
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
    assert allow == {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'allow'}}

    deny = codex.build_hook_response(HookDecision.deny(AiHookEventType.MCP_EXECUTION, 'secret in args!'))
    assert deny == {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': 'deny',
            'permissionDecisionReason': 'secret in args!',
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
    for mode in (False, True):
        rendered = Codex().render_hooks_config(async_mode=mode)
        for entry in rendered['hooks']['PreToolUse']:
            for hook in entry['hooks']:
                assert 'async' not in hook
                assert 'timeout' not in hook


def test_render_hooks_async_backgrounds_scan_hooks() -> None:
    """In async mode, UserPromptSubmit + PreToolUse scan hooks shell-background."""
    rendered = Codex().render_hooks_config(async_mode=True)
    prompt_cmd = rendered['hooks']['UserPromptSubmit'][0]['hooks'][0]['command']
    pretool_cmd = rendered['hooks']['PreToolUse'][0]['hooks'][0]['command']
    assert prompt_cmd.endswith(' &')
    assert pretool_cmd.endswith(' &')


def test_render_hooks_session_start_always_synchronous() -> None:
    """SessionStart registers the conversation context — never backgrounded."""
    for mode in (False, True):
        rendered = Codex().render_hooks_config(async_mode=mode)
        session_cmd = rendered['hooks']['SessionStart'][0]['hooks'][0]['command']
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
    return f'{header}.{payload}.signature-not-verified'


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
        global_config_file, plugins = Codex().get_session_context()
    assert global_config_file is not None
    assert global_config_file['path'].endswith('config.toml')
    assert global_config_file['content'] == json.dumps({'mcpServers': mcp})
    assert plugins == {}


def test_session_context_no_config() -> None:
    with patch('cycode.cli.apps.ai_guardrails.ides.codex._load_codex_config', return_value=None):
        global_config_file, plugins = Codex().get_session_context()
    assert global_config_file is None
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
    # Codex MCP files may be a bare {name: cfg} map with no mcpServers wrapper.
    mcp_content = {'dummy-server': {'command': 'dummy-command'}}
    _write_codex_plugin(tmp_path, mcp_content)

    entry, servers = _read_codex_plugin(tmp_path)

    assert json.loads(entry['mcp_config_file']) == mcp_content
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
