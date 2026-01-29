"""Unified payload object for AI hook events from different tools."""

from dataclasses import dataclass
from typing import Optional

from cycode.cli.apps.ai_guardrails.scan.types import CURSOR_EVENT_MAPPING


@dataclass
class AIHookPayload:
    """Unified payload object that normalizes field names from different AI tools."""

    # Event identification
    event_name: str  # Canonical event type (e.g., 'prompt', 'file_read', 'mcp_execution')
    conversation_id: Optional[str] = None
    generation_id: Optional[str] = None

    # User and IDE information
    ide_user_email: Optional[str] = None
    model: Optional[str] = None
    ide_provider: str = None  # e.g., 'cursor', 'claude-code'
    ide_version: Optional[str] = None

    # Event-specific data
    prompt: Optional[str] = None  # For prompt events
    file_path: Optional[str] = None  # For file_read events
    mcp_server_name: Optional[str] = None  # For mcp_execution events
    mcp_tool_name: Optional[str] = None  # For mcp_execution events
    mcp_arguments: Optional[dict] = None  # For mcp_execution events

    @classmethod
    def from_cursor_payload(cls, payload: dict) -> 'AIHookPayload':
        """Create AIHookPayload from Cursor IDE payload.

        Maps Cursor-specific event names to canonical event types.
        """
        cursor_event_name = payload.get('hook_event_name', '')
        # Map Cursor event name to canonical type, fallback to original if not found
        canonical_event = CURSOR_EVENT_MAPPING.get(cursor_event_name, cursor_event_name)

        return cls(
            event_name=canonical_event,
            conversation_id=payload.get('conversation_id'),
            generation_id=payload.get('generation_id'),
            ide_user_email=payload.get('user_email'),
            model=payload.get('model'),
            ide_provider='cursor',
            ide_version=payload.get('cursor_version'),
            prompt=payload.get('prompt', ''),
            file_path=payload.get('file_path') or payload.get('path'),
            mcp_server_name=payload.get('command'),  # MCP server name
            mcp_tool_name=payload.get('tool_name') or payload.get('tool'),
            mcp_arguments=payload.get('arguments') or payload.get('tool_input') or payload.get('input'),
        )

    @classmethod
    def from_payload(cls, payload: dict, tool: str = 'cursor') -> 'AIHookPayload':
        """Create AIHookPayload from any tool's payload.

        Args:
            payload: The raw payload from the IDE
            tool: The IDE/tool name (e.g., 'cursor')

        Returns:
            AIHookPayload instance

        Raises:
            ValueError: If the tool is not supported
        """
        if tool == 'cursor':
            return cls.from_cursor_payload(payload)
        raise ValueError(f'Unsupported IDE/tool: {tool}.')
