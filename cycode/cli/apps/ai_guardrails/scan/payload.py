"""Canonical AI hook payload shared across IDE integrations.

The dataclass is populated by `IDE.parse_hook_payload` (see
`cycode/cli/apps/ai_guardrails/ides/`). Per-IDE parsing logic lives on the
respective IDE class.
"""

import uuid
from dataclasses import dataclass, field


@dataclass
class AIHookPayload:
    """Unified payload that normalizes field names across IDEs."""

    # Event identification
    event_name: str | None = None  # Canonical event type from AiHookEventType
    conversation_id: str | None = None
    generation_id: str | None = None

    # Minted here rather than by the server: the guardrail scan and the hook event are reported in two
    # separate requests, and both have to name the same event. A generation id can't stand in for it - the
    # IDE mints one per prompt, so several hook events share it, and some IDEs don't supply one at all.
    hook_event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # User and IDE information
    ide_user_email: str | None = None
    model: str | None = None
    ide_provider: str | None = None  # Matches IDE.name (e.g. 'cursor', 'claude-code')
    ide_version: str | None = None

    source: str | None = None

    # Event-specific data
    prompt: str | None = None  # PROMPT events
    file_path: str | None = None  # FILE_READ events
    mcp_server_name: str | None = None  # MCP_EXECUTION events
    mcp_tool_name: str | None = None
    mcp_arguments: dict | None = None
