"""Claude Code IDE integration for AI guardrails."""

import json
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from typing import ClassVar, Optional

from cycode.cli.apps.ai_guardrails.consts import CYCODE_SCAN_PROMPT_COMMAND, CYCODE_SESSION_START_COMMAND
from cycode.cli.apps.ai_guardrails.ides._plugin_utils import load_plugin_json, walk_enabled_plugins
from cycode.cli.apps.ai_guardrails.ides.base import IDE, DecisionAction, HookDecision
from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType
from cycode.logger import get_logger

logger = get_logger('AI Guardrails Claude Code')

_CLAUDE_CODE_EVENT_NAMES = frozenset({'UserPromptSubmit', 'PreToolUse'})

_USER_HOOKS_DIR = Path.home() / '.claude'
_HOOKS_FILE_NAME = 'settings.json'
_REPO_SUBDIR = '.claude'
_HOOK_EVENTS = ['UserPromptSubmit', 'PreToolUse:Read', 'PreToolUse:mcp']

_CLAUDE_CONFIG_PATH = Path.home() / '.claude.json'
_CLAUDE_SETTINGS_PATH = Path.home() / '.claude' / 'settings.json'

_SCAN_COMMAND = f'{CYCODE_SCAN_PROMPT_COMMAND} --ide claude-code'
_SESSION_START_COMMAND = f'{CYCODE_SESSION_START_COMMAND} --ide claude-code'


# --- transcript JSONL parsing -------------------------------------------------


def _reverse_readline(path: Path, buf_size: int = 8192) -> Iterator[str]:
    """Yield lines of `path` from end to start without loading the file.

    The Claude Code transcript can be very large; reading from the tail keeps
    memory bounded since we only care about the most recent entries.
    """
    with path.open('rb') as f:
        f.seek(0, 2)
        file_size = f.tell()
        if file_size == 0:
            return

        remaining = file_size
        buffer = b''

        while remaining > 0:
            read_size = min(buf_size, remaining)
            remaining -= read_size
            f.seek(remaining)
            chunk = f.read(read_size)
            buffer = chunk + buffer

            while b'\n' in buffer:
                newline_pos = buffer.rfind(b'\n')
                if newline_pos == len(buffer) - 1:
                    newline_pos = buffer.rfind(b'\n', 0, newline_pos)
                    if newline_pos == -1:
                        break
                line = buffer[newline_pos + 1 :]
                buffer = buffer[: newline_pos + 1]
                if line.strip():
                    yield line.decode('utf-8', errors='replace')

        if buffer.strip():
            yield buffer.decode('utf-8', errors='replace')


def _extract_model(entry: dict) -> Optional[str]:
    """Extract model from a transcript entry (top level or nested in message)."""
    return entry.get('model') or (entry.get('message') or {}).get('model')


def _extract_generation_id(entry: dict) -> Optional[str]:
    """Extract generation ID from a user-type transcript entry."""
    if entry.get('type') == 'user':
        return entry.get('uuid')
    return None


def extract_from_claude_transcript(
    transcript_path: str,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract ``(ide_version, model, generation_id)`` from a transcript.

    The transcript is a JSONL file scanned from end → start so the most recent
    entries are read first. Any field may come back ``None`` if not found.
    """
    if not transcript_path:
        return None, None, None

    path = Path(transcript_path)
    if not path.exists():
        return None, None, None

    ide_version = None
    model = None
    generation_id = None

    try:
        for line in _reverse_readline(path):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                ide_version = ide_version or entry.get('version')
                model = model or _extract_model(entry)
                generation_id = generation_id or _extract_generation_id(entry)

                if ide_version and model and generation_id:
                    break
            except json.JSONDecodeError:
                continue
    except OSError:
        pass

    return ide_version, model, generation_id


# --- ~/.claude.json + ~/.claude/settings.json parsing -------------------------


def load_claude_config(config_path: Optional[Path] = None) -> Optional[dict]:
    """Load and parse `~/.claude.json`. Returns None if missing/invalid."""
    path = config_path or _CLAUDE_CONFIG_PATH
    if not path.exists():
        logger.debug('Claude config file not found, %s', {'path': str(path)})
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception as e:
        logger.debug('Failed to load Claude config file', exc_info=e)
        return None


def _email_from_config(config: dict) -> Optional[str]:
    """Read ``oauthAccount.emailAddress`` from a parsed Claude config."""
    return config.get('oauthAccount', {}).get('emailAddress')


def get_mcp_servers(config: dict) -> Optional[dict]:
    """Read ``mcpServers`` from a parsed Claude config."""
    return config.get('mcpServers')


def load_claude_settings(settings_path: Optional[Path] = None) -> Optional[dict]:
    """Load and parse `~/.claude/settings.json`. Returns None if missing/invalid."""
    path = settings_path or _CLAUDE_SETTINGS_PATH
    if not path.exists():
        logger.debug('Claude settings file not found, %s', {'path': str(path)})
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception as e:
        logger.debug('Failed to load Claude settings file', exc_info=e)
        return None


def _resolve_marketplace_path(marketplace: dict) -> Optional[Path]:
    """Resolve filesystem path for a directory-type marketplace."""
    source = marketplace.get('source', {})
    if source.get('source') != 'directory':
        return None
    raw = source.get('path')
    if not raw:
        return None
    path = Path(raw)
    return path if path.is_dir() else None


def _read_claude_plugin(plugin_dir: Path) -> tuple[dict, dict]:
    """Read one Claude Code plugin's manifest + MCP servers.

    Claude hardcodes the MCP file at ``<plugin_dir>/.mcp.json`` and always
    wraps it as ``{"mcpServers": {...}}``.
    """
    manifest = load_plugin_json(plugin_dir / '.claude-plugin' / 'plugin.json') or {}
    entry: dict = {}
    for field in ('name', 'version', 'description'):
        if field in manifest:
            entry[field] = manifest[field]

    mcp_config = load_plugin_json(plugin_dir / '.mcp.json') or {}
    servers: dict = mcp_config.get('mcpServers') or {}
    if servers:
        entry['mcp_server_names'] = list(servers.keys())
        entry['mcp_config_file'] = json.dumps(mcp_config)
    return entry, servers


def resolve_plugins(settings: dict) -> tuple[dict, dict]:
    """Walk Claude Code's ``enabledPlugins`` via the shared plugin walker.

    Each enabled plugin's marketplace is resolved through
    ``extraKnownMarketplaces`` to a directory; the rest of the work
    (manifest + ``.mcp.json``) is the shared ``_read_claude_plugin``.
    """
    enabled = settings.get('enabledPlugins') or {}
    marketplaces = settings.get('extraKnownMarketplaces') or {}

    def _locate(_plugin_name: str, marketplace_name: str) -> Optional[Path]:
        marketplace = marketplaces.get(marketplace_name)
        if not marketplace:
            return None
        return _resolve_marketplace_path(marketplace)

    return walk_enabled_plugins(
        plugin_entries=enabled,
        is_enabled=bool,
        locate_dir=_locate,
        read_plugin=_read_claude_plugin,
    )


# --- IDE integration ----------------------------------------------------------


class ClaudeCode(IDE):
    name: ClassVar[str] = 'claude-code'
    display_name: ClassVar[str] = 'Claude Code'
    hook_events: ClassVar[list[str]] = list(_HOOK_EVENTS)

    def settings_path(self, scope: str, repo_path: Optional[Path] = None) -> Path:
        if scope == 'repo' and repo_path:
            return repo_path / _REPO_SUBDIR / _HOOKS_FILE_NAME
        return _USER_HOOKS_DIR / _HOOKS_FILE_NAME

    def render_hooks_config(self, async_mode: bool = False) -> dict:
        # Claude Code uses a nested hook structure with optional async/timeout.
        hook_entry: dict = {'type': 'command', 'command': _SCAN_COMMAND}
        if async_mode:
            hook_entry['async'] = True
            hook_entry['timeout'] = 20

        return {
            'hooks': {
                'SessionStart': [
                    {
                        'matcher': 'startup|clear',
                        'hooks': [{'type': 'command', 'command': _SESSION_START_COMMAND}],
                    }
                ],
                'UserPromptSubmit': [
                    {
                        'hooks': [deepcopy(hook_entry)],
                    }
                ],
                'PreToolUse': [
                    {
                        'matcher': 'Read',
                        'hooks': [deepcopy(hook_entry)],
                    },
                    {
                        'matcher': 'mcp__.*',
                        'hooks': [deepcopy(hook_entry)],
                    },
                ],
            },
        }

    def matches_payload(self, raw_payload: dict) -> bool:
        return raw_payload.get('hook_event_name', '') in _CLAUDE_CODE_EVENT_NAMES

    def parse_hook_payload(self, raw_payload: dict) -> AIHookPayload:
        hook_event_name = raw_payload.get('hook_event_name', '')
        tool_name = raw_payload.get('tool_name', '')
        tool_input = raw_payload.get('tool_input')

        if hook_event_name == 'UserPromptSubmit':
            canonical_event: AiHookEventType | str = AiHookEventType.PROMPT
        elif hook_event_name == 'PreToolUse':
            canonical_event = AiHookEventType.FILE_READ if tool_name == 'Read' else AiHookEventType.MCP_EXECUTION
        else:
            canonical_event = hook_event_name

        # Extract file_path from tool_input for the Read tool.
        file_path = None
        if tool_name == 'Read' and isinstance(tool_input, dict):
            file_path = tool_input.get('file_path')

        # For MCP tools, the entire tool_input is the arguments.
        mcp_arguments = tool_input if tool_name.startswith('mcp__') else None

        # MCP tool name format: mcp__<server>__<tool>
        mcp_server_name = None
        mcp_tool_name = None
        if tool_name.startswith('mcp__'):
            parts = tool_name.split('__')
            if len(parts) >= 2:
                mcp_server_name = parts[1]
            if len(parts) >= 3:
                mcp_tool_name = parts[2]

        ide_version, model, generation_id = extract_from_claude_transcript(raw_payload.get('transcript_path'))

        config = load_claude_config()
        ide_user_email = _email_from_config(config) if config else None

        return AIHookPayload(
            event_name=canonical_event,
            conversation_id=raw_payload.get('session_id'),
            generation_id=generation_id,
            ide_user_email=ide_user_email,
            model=model,
            ide_provider=self.name,
            ide_version=ide_version,
            prompt=raw_payload.get('prompt', ''),
            file_path=file_path,
            mcp_server_name=mcp_server_name,
            mcp_tool_name=mcp_tool_name,
            mcp_arguments=mcp_arguments,
        )

    def build_hook_response(self, decision: HookDecision) -> dict:
        if decision.event_type == AiHookEventType.PROMPT:
            if decision.action == DecisionAction.ALLOW:
                return {}
            # Both DENY and (unexpected) ASK on prompts collapse to a block.
            return {'decision': 'block', 'reason': decision.user_message or ''}

        # FILE_READ / MCP_EXECUTION → hookSpecificOutput shape.
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
        config = load_claude_config()
        ide_user_email = _email_from_config(config) if config else None
        ide_version, _, _ = extract_from_claude_transcript(raw_payload.get('transcript_path'))

        return AIHookPayload(
            conversation_id=raw_payload.get('session_id'),
            ide_user_email=ide_user_email,
            model=raw_payload.get('model'),
            ide_provider=self.name,
            ide_version=ide_version,
            source=raw_payload.get('source'),
        )

    def get_user_email(self) -> Optional[str]:
        config = load_claude_config()
        return _email_from_config(config) if config else None

    def get_session_context(self) -> tuple[dict, dict]:
        config = load_claude_config()
        mcp_servers: dict = dict(get_mcp_servers(config) or {}) if config else {}

        settings = load_claude_settings()
        if settings:
            plugin_mcp, enriched_plugins = resolve_plugins(settings)
            mcp_servers.update(plugin_mcp)
        else:
            enriched_plugins = {}

        return mcp_servers, enriched_plugins
