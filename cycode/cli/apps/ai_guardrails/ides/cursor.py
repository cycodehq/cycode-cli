"""Cursor IDE integration for AI guardrails."""

import json
import platform
from pathlib import Path
from typing import ClassVar, Optional

from cycode.cli.apps.ai_guardrails.consts import CYCODE_SCAN_PROMPT_COMMAND, CYCODE_SESSION_START_COMMAND
from cycode.cli.apps.ai_guardrails.ides._plugin_utils import build_global_config_file
from cycode.cli.apps.ai_guardrails.ides.base import IDE, DecisionAction, HookDecision
from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType
from cycode.logger import get_logger

logger = get_logger('AI Guardrails Cursor')

_CURSOR_EVENT_MAPPING: dict[str, AiHookEventType] = {
    'beforeSubmitPrompt': AiHookEventType.PROMPT,
    'beforeReadFile': AiHookEventType.FILE_READ,
    'beforeMCPExecution': AiHookEventType.MCP_EXECUTION,
}

_HOOKS_FILE_NAME = 'hooks.json'
_REPO_SUBDIR = '.cursor'
_MCP_CONFIG_FILENAME = 'mcp.json'

# Cursor was the original default IDE — its scan command omits --ide to stay
# byte-identical with already-installed hooks.json files. Session-start is
# always explicit because it was introduced after Claude Code support.
_SCAN_COMMAND = CYCODE_SCAN_PROMPT_COMMAND
_SESSION_START_COMMAND = f'{CYCODE_SESSION_START_COMMAND} --ide cursor'


def _user_hooks_dir() -> Path:
    """Per-platform Cursor user-scope settings directory."""
    if platform.system() == 'Darwin':
        return Path.home() / '.cursor'
    if platform.system() == 'Windows':
        return Path.home() / 'AppData' / 'Roaming' / 'Cursor'
    return Path.home() / '.config' / 'Cursor'


def _cursor_mcp_config_path() -> Path:
    """User-scope Cursor MCP config path (``~/.cursor/mcp.json``, all platforms)."""
    return Path.home() / '.cursor' / _MCP_CONFIG_FILENAME


def _load_cursor_mcp_config(config_path: Optional[Path] = None) -> Optional[dict]:
    """Load and parse `~/.cursor/mcp.json`. Returns None if missing/invalid."""
    path = config_path or _cursor_mcp_config_path()
    if not path.exists():
        logger.debug('Cursor MCP config file not found, %s', {'path': str(path)})
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception as e:
        logger.debug('Failed to load Cursor MCP config file', exc_info=e)
        return None


class Cursor(IDE):
    name: ClassVar[str] = 'cursor'
    display_name: ClassVar[str] = 'Cursor'
    hook_events: ClassVar[list[str]] = list(_CURSOR_EVENT_MAPPING)

    def settings_path(self, scope: str, repo_path: Optional[Path] = None) -> Path:
        if scope == 'repo' and repo_path:
            return repo_path / _REPO_SUBDIR / _HOOKS_FILE_NAME
        return _user_hooks_dir() / _HOOKS_FILE_NAME

    def render_hooks_config(self, async_mode: bool = False) -> dict:
        command = f'{_SCAN_COMMAND} &' if async_mode else _SCAN_COMMAND
        hooks = {event: [{'command': command}] for event in self.hook_events}
        hooks['sessionStart'] = [{'command': _SESSION_START_COMMAND}]
        return {'version': 1, 'hooks': hooks}

    def matches_payload(self, raw_payload: dict) -> bool:
        return raw_payload.get('hook_event_name', '') in _CURSOR_EVENT_MAPPING

    def parse_hook_payload(self, raw_payload: dict) -> AIHookPayload:
        cursor_event_name = raw_payload.get('hook_event_name', '')
        canonical_event = _CURSOR_EVENT_MAPPING.get(cursor_event_name, cursor_event_name)
        return AIHookPayload(
            event_name=canonical_event,
            conversation_id=raw_payload.get('conversation_id'),
            generation_id=raw_payload.get('generation_id'),
            ide_user_email=raw_payload.get('user_email'),
            model=raw_payload.get('model'),
            ide_provider=self.name,
            ide_version=raw_payload.get('cursor_version'),
            prompt=raw_payload.get('prompt', ''),
            file_path=raw_payload.get('file_path') or raw_payload.get('path'),
            mcp_server_name=raw_payload.get('command'),
            mcp_tool_name=raw_payload.get('tool_name') or raw_payload.get('tool'),
            mcp_arguments=(raw_payload.get('arguments') or raw_payload.get('tool_input') or raw_payload.get('input')),
        )

    def build_hook_response(self, decision: HookDecision) -> dict:
        if decision.event_type == AiHookEventType.PROMPT:
            if decision.action == DecisionAction.ALLOW:
                return {'continue': True}
            return {'continue': False, 'user_message': decision.user_message or ''}

        # FILE_READ / MCP_EXECUTION → permission shape
        if decision.action == DecisionAction.ALLOW:
            return {'permission': 'allow'}
        return {
            'permission': decision.action.value,  # 'deny' or 'ask'
            'user_message': decision.user_message or '',
            'agent_message': decision.agent_message or '',
        }

    def build_session_payload(self, raw_payload: dict) -> AIHookPayload:
        return AIHookPayload(
            conversation_id=raw_payload.get('conversation_id'),
            ide_user_email=raw_payload.get('user_email'),
            model=raw_payload.get('model'),
            ide_provider=self.name,
            ide_version=raw_payload.get('cursor_version'),
        )

    def get_session_context(self) -> tuple[Optional[dict], dict]:
        config = _load_cursor_mcp_config()
        if not config:
            return None, {}
        config_path = _cursor_mcp_config_path()
        global_config_file = build_global_config_file(config_path, config.get('mcpServers'))
        return global_config_file, {}
