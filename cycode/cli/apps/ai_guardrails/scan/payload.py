"""Canonical AI hook payload shared across IDE integrations.

The dataclass is populated by `IDE.parse_hook_payload` (see
`cycode/cli/apps/ai_guardrails/ides/`). Per-IDE parsing logic lives on the
respective IDE class.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class AIHookPayload:
    """Unified payload that normalizes field names across IDEs."""

    # Event identification
    event_name: Optional[str] = None  # Canonical event type from AiHookEventType
    conversation_id: Optional[str] = None
    generation_id: Optional[str] = None

    # User and IDE information
    ide_user_email: Optional[str] = None
    model: Optional[str] = None
    ide_provider: Optional[str] = None  # Matches IDE.name (e.g. 'cursor', 'claude-code')
    ide_version: Optional[str] = None

    source: Optional[str] = None

    # Event-specific data
    prompt: Optional[str] = None  # PROMPT events
    file_path: Optional[str] = None  # FILE_READ events
    mcp_server_name: Optional[str] = None  # MCP_EXECUTION events
    mcp_tool_name: Optional[str] = None
    mcp_arguments: Optional[dict] = None
