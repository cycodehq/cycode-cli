"""Codex CLI IDE integration for AI guardrails."""

import json
import os
import sys
from pathlib import Path
from typing import ClassVar, Optional

import tomli_w

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - py<3.11 fallback
    import tomli as tomllib

from cycode.cli.apps.ai_guardrails.consts import CYCODE_SCAN_PROMPT_COMMAND, CYCODE_SESSION_START_COMMAND
from cycode.cli.apps.ai_guardrails.ides._plugin_utils import (
    build_global_config_file,
    load_plugin_json,
    resolve_cached_plugin_dir,
    walk_enabled_plugins,
)
from cycode.cli.apps.ai_guardrails.ides.base import IDE, DecisionAction, HookDecision, shell_background_suffix
from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType
from cycode.cli.utils.jwt_utils import decode_jwt_unverified
from cycode.logger import get_logger

logger = get_logger('AI Guardrails Codex')

_CONFIG_DIR_NAME = '.codex'
_HOOKS_FILE_NAME = 'hooks.json'
_CONFIG_TOML_NAME = 'config.toml'
_AUTH_JSON_NAME = 'auth.json'
_CODEX_HOME_ENV_VAR = 'CODEX_HOME'

_HOOK_EVENTS = ('UserPromptSubmit', 'PreToolUse:mcp')
_CODEX_EVENT_NAMES = frozenset(e.split(':', 1)[0] for e in _HOOK_EVENTS)

_SCAN_COMMAND = f'{CYCODE_SCAN_PROMPT_COMMAND} --ide codex'
_SESSION_START_COMMAND = f'{CYCODE_SESSION_START_COMMAND} --ide codex'


def _codex_home() -> Path:
    """Resolve Codex's user-scope home directory.

    Honors ``$CODEX_HOME`` per Codex's documented override; falls back to
    ``~/.codex``.
    """
    override = os.environ.get(_CODEX_HOME_ENV_VAR)
    if override:
        return Path(override)
    return Path.home() / _CONFIG_DIR_NAME


def _codex_config_toml_path(scope: str, repo_path: Optional[Path] = None) -> Path:
    """Return the Codex ``config.toml`` path for the given scope."""
    if scope == 'repo' and repo_path:
        return repo_path / _CONFIG_DIR_NAME / _CONFIG_TOML_NAME
    return _codex_home() / _CONFIG_TOML_NAME


def _load_codex_config(config_path: Optional[Path] = None) -> Optional[dict]:
    """Load and parse Codex's ``config.toml``. Returns None on missing/invalid."""
    path = config_path or (_codex_home() / _CONFIG_TOML_NAME)
    if not path.exists():
        logger.debug('Codex config file not found, %s', {'path': str(path)})
        return None
    try:
        with path.open('rb') as f:
            return tomllib.load(f)
    except Exception as e:
        logger.debug('Failed to load Codex config file, %s', {'path': str(path)}, exc_info=e)
        return None


def _email_from_auth(auth_path: Optional[Path] = None) -> Optional[str]:
    """Best-effort extraction of the signed-in Codex user's email.

    Reads ``~/.codex/auth.json`` and decodes the JWT in ``tokens.id_token``
    to pull the ``email`` claim. Returns None if auth.json is missing
    (``OPENAI_API_KEY``-only setups, OS keychain credentials) or unreadable.
    """
    path = auth_path or (_codex_home() / _AUTH_JSON_NAME)
    if not path.exists():
        logger.debug('Codex auth file not found, %s', {'path': str(path)})
        return None
    try:
        auth = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as e:
        logger.debug('Failed to load Codex auth file, %s', {'path': str(path)}, exc_info=e)
        return None

    token = (auth.get('tokens') or {}).get('id_token')
    if not token:
        return None
    claims = decode_jwt_unverified(token)
    if not claims:
        return None
    return claims.get('email')


def _resolve_codex_plugin_dir(plugin_name: str, marketplace: str) -> Optional[Path]:
    """Find ``~/.codex/plugins/cache/<marketplace>/<plugin>/<hash>/``."""
    return resolve_cached_plugin_dir(_codex_home() / 'plugins' / 'cache', marketplace, plugin_name)


def _read_codex_plugin(plugin_dir: Path) -> tuple[dict, dict]:
    """Read one Codex plugin's manifest + MCP servers.

    Codex's manifest references the MCP file via a path string in the
    ``mcpServers`` field (default ``./.mcp.json``); the target file is either
    a bare ``{name: cfg}`` map or wrapped in ``{"mcpServers": {...}}``.
    """
    manifest = load_plugin_json(plugin_dir / '.codex-plugin' / 'plugin.json')
    entry: dict = {}
    if not manifest:
        return entry, {}

    for field in ('name', 'version', 'description'):
        if field in manifest:
            entry[field] = manifest[field]

    mcp_ref = manifest.get('mcpServers')
    if not mcp_ref:
        return entry, {}
    mcp_config_path = plugin_dir / mcp_ref
    mcp_doc = load_plugin_json(mcp_config_path) or {}
    servers = mcp_doc.get('mcpServers', mcp_doc)
    if not isinstance(servers, dict):
        servers = {}
    if servers:
        entry['mcp_server_names'] = list(servers.keys())
        entry['mcp_config_file_path'] = str(mcp_config_path)
        entry['mcp_config_file'] = json.dumps({'mcpServers': servers})
    return entry, servers


def _resolve_codex_plugins(config: dict) -> dict:
    """Walk enabled ``[plugins."<plugin>@<marketplace>"]`` entries."""
    return walk_enabled_plugins(
        plugin_entries=config.get('plugins') or {},
        is_enabled=lambda s: isinstance(s, dict) and bool(s.get('enabled')),
        locate_dir=_resolve_codex_plugin_dir,
        read_plugin=_read_codex_plugin,
    )


def _enable_codex_hooks_feature(scope: str, repo_path: Optional[Path] = None) -> tuple[bool, str]:
    """Set ``[features] hooks = true`` in Codex's ``config.toml``.

    Codex's hook scripts are gated behind this feature flag. We preserve any
    existing keys and create the file (+ parent dir) when missing.
    """
    config_path = _codex_config_toml_path(scope, repo_path)

    config: dict = {}
    if config_path.exists():
        try:
            with config_path.open('rb') as f:
                config = tomllib.load(f)
        except Exception as e:
            logger.error('Failed to parse Codex config.toml, %s', {'path': str(config_path)}, exc_info=e)
            return False, f'Failed to parse existing Codex config at {config_path}'

    features = config.get('features')
    if not isinstance(features, dict):
        features = {}
    features['hooks'] = True
    config['features'] = features

    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with config_path.open('wb') as f:
            tomli_w.dump(config, f)
        return True, f'Enabled hooks feature in {config_path}'
    except Exception as e:
        logger.error('Failed to write Codex config.toml, %s', {'path': str(config_path)}, exc_info=e)
        return False, f'Failed to write Codex config at {config_path}'


class Codex(IDE):
    name: ClassVar[str] = 'codex'
    display_name: ClassVar[str] = 'Codex'
    hook_events: ClassVar[list[str]] = list(_HOOK_EVENTS)

    def settings_path(self, scope: str, repo_path: Optional[Path] = None) -> Path:
        if scope == 'repo' and repo_path:
            return repo_path / _CONFIG_DIR_NAME / _HOOKS_FILE_NAME
        return _codex_home() / _HOOKS_FILE_NAME

    def render_hooks_config(self, async_mode: bool = False) -> dict:
        # Codex's TOML `async: true` flag is unimplemented; shell-background via
        # `&` is the working mechanism (unix only). SessionStart stays sync so
        # the conversation context is registered before any scan hook fires.
        scan_cmd = f'{_SCAN_COMMAND}{shell_background_suffix(async_mode)}'
        return {
            'hooks': {
                'SessionStart': [
                    {
                        'hooks': [{'type': 'command', 'command': _SESSION_START_COMMAND}],
                    }
                ],
                'UserPromptSubmit': [
                    {
                        'hooks': [{'type': 'command', 'command': scan_cmd}],
                    }
                ],
                'PreToolUse': [
                    {
                        'matcher': 'mcp__.*',
                        'hooks': [{'type': 'command', 'command': scan_cmd}],
                    },
                ],
            },
        }

    def post_install(self, scope: str, repo_path: Optional[Path] = None) -> tuple[bool, str]:
        return _enable_codex_hooks_feature(scope, repo_path)

    def matches_payload(self, raw_payload: dict) -> bool:
        return raw_payload.get('hook_event_name', '') in _CODEX_EVENT_NAMES

    def parse_hook_payload(self, raw_payload: dict) -> AIHookPayload:
        hook_event_name = raw_payload.get('hook_event_name', '')
        tool_name = raw_payload.get('tool_name', '')
        tool_input = raw_payload.get('tool_input')

        if hook_event_name == 'UserPromptSubmit':
            canonical_event: AiHookEventType | str = AiHookEventType.PROMPT
        elif hook_event_name == 'PreToolUse' and tool_name.startswith('mcp__'):
            canonical_event = AiHookEventType.MCP_EXECUTION
        else:
            canonical_event = hook_event_name

        mcp_server_name = None
        mcp_tool_name = None
        mcp_arguments = None
        if tool_name.startswith('mcp__'):
            parts = tool_name.split('__')
            if len(parts) >= 2:
                mcp_server_name = parts[1]
            if len(parts) >= 3:
                mcp_tool_name = parts[2]
            mcp_arguments = tool_input

        return AIHookPayload(
            event_name=canonical_event,
            conversation_id=raw_payload.get('session_id'),
            generation_id=raw_payload.get('turn_id'),
            ide_user_email=_email_from_auth(),
            model=raw_payload.get('model'),
            ide_provider=self.name,
            prompt=raw_payload.get('prompt', ''),
            mcp_server_name=mcp_server_name,
            mcp_tool_name=mcp_tool_name,
            mcp_arguments=mcp_arguments,
        )

    def build_hook_response(self, decision: HookDecision) -> dict:
        # Codex accepts the same hook response shapes as Claude Code:
        #  - PROMPT: empty for allow, {"decision": "block", "reason": ...} for deny
        #  - PreToolUse: hookSpecificOutput.permissionDecision
        if decision.event_type == AiHookEventType.PROMPT:
            if decision.action == DecisionAction.ALLOW:
                return {}
            return {'decision': 'block', 'reason': decision.user_message or ''}

        if decision.action == DecisionAction.ALLOW:
            return {
                'hookSpecificOutput': {
                    'hookEventName': 'PreToolUse',
                    'permissionDecision': 'allow',
                }
            }
        return {
            'hookSpecificOutput': {
                'hookEventName': 'PreToolUse',
                'permissionDecision': decision.action.value,  # 'deny' or 'ask'
                'permissionDecisionReason': decision.user_message or '',
            }
        }

    def build_session_payload(self, raw_payload: dict) -> AIHookPayload:
        return AIHookPayload(
            conversation_id=raw_payload.get('session_id'),
            ide_user_email=_email_from_auth(),
            model=raw_payload.get('model'),
            ide_provider=self.name,
            ide_version=raw_payload.get('codex_version'),
            source=raw_payload.get('source'),
        )

    def get_user_email(self) -> Optional[str]:
        return _email_from_auth()

    def get_session_context(self) -> tuple[Optional[dict], dict]:
        config = _load_codex_config()
        if not config:
            return None, {}
        # Codex stores MCP servers under `[mcp_servers.<name>]`; the global config
        # file becomes its own session-context file. Plugins (via
        # `[plugins."<plugin>@<marketplace>"]`) carry their own config files.
        config_path = _codex_config_toml_path('user')
        global_config_file = build_global_config_file(config_path, config.get('mcp_servers'))
        enriched_plugins = _resolve_codex_plugins(config)
        return global_config_file, enriched_plugins
