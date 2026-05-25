"""Base abstractions for AI guardrails IDE integrations.

Each AI IDE (Cursor, Claude Code, …) is represented by a subclass of `IDE`
that consolidates every IDE-specific concern in a single module: settings file
paths, hooks template rendering, payload parsing, response building, and any
IDE-specific session-context lookup.

Adding a new IDE is a matter of:
  1. Subclassing `IDE` and implementing the abstract methods.
  2. Registering the instance in `cycode/cli/apps/ai_guardrails/ides/__init__.py`.

The `HookDecision` dataclass is the canonical, IDE-agnostic return type for
event handlers; `IDE.build_hook_response` translates it into the IDE-specific
JSON response shape that the IDE expects on stdout.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import ClassVar, Optional

from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType


class DecisionAction(str, Enum):
    """Canonical decision action returned by event handlers."""

    ALLOW = 'allow'
    DENY = 'deny'
    ASK = 'ask'


@dataclass(frozen=True)
class HookDecision:
    """Canonical, IDE-agnostic decision returned by event handlers.

    Carries the event type so `IDE.build_hook_response` can pick the right
    IDE-specific response shape (Cursor's "permission" style for tool events
    vs. "continue" style for prompts; Claude Code's "hookSpecificOutput"
    vs. "decision: block").
    """

    action: DecisionAction
    event_type: AiHookEventType
    user_message: Optional[str] = None
    agent_message: Optional[str] = None

    @classmethod
    def allow(cls, event_type: AiHookEventType) -> 'HookDecision':
        return cls(action=DecisionAction.ALLOW, event_type=event_type)

    @classmethod
    def deny(
        cls, event_type: AiHookEventType, user_message: str, agent_message: Optional[str] = None
    ) -> 'HookDecision':
        return cls(
            action=DecisionAction.DENY,
            event_type=event_type,
            user_message=user_message,
            agent_message=agent_message,
        )

    @classmethod
    def ask(cls, event_type: AiHookEventType, user_message: str, agent_message: Optional[str] = None) -> 'HookDecision':
        return cls(
            action=DecisionAction.ASK,
            event_type=event_type,
            user_message=user_message,
            agent_message=agent_message,
        )


class IDE(ABC):
    """Per-IDE integration. Owns every IDE-specific concern in a single module.

    Subclasses declare identity via class attributes and implement the abstract
    methods. Defaults are provided for `get_user_email` and `get_session_context`
    so IDEs without those capabilities (e.g. no plugin system, no local
    account file) can skip them.
    """

    # CLI value passed to --ide (e.g. 'cursor', 'claude-code').
    name: ClassVar[str]
    # Human-friendly name for output ('Cursor', 'Claude Code').
    display_name: ClassVar[str]
    # Event names for status display. Use '<event>:<matcher>' for IDEs that
    # qualify a single hook by a sub-matcher (e.g. Claude Code's PreToolUse:Read).
    hook_events: ClassVar[list[str]]

    # --- install / status ---

    @abstractmethod
    def settings_path(self, scope: str, repo_path: Optional[Path] = None) -> Path:
        """Return the hooks/settings file path for the given scope.

        `scope` is 'user' or 'repo'. `repo_path` is required when scope == 'repo'.
        """

    @abstractmethod
    def render_hooks_config(self, async_mode: bool = False) -> dict:
        """Return the settings blob to merge into the IDE's settings file.

        Shape is IDE-specific (Cursor uses a flat ``{event: [{command}]}`` dict;
        Claude Code uses a nested ``{event: [{hooks: [{type, command}]}]}``
        dict). Both share the outer ``{"hooks": ...}`` wrapper so
        ``hooks_manager`` can treat them uniformly.
        """

    # --- runtime scan ---

    @abstractmethod
    def matches_payload(self, raw_payload: dict) -> bool:
        """Return True if ``raw_payload`` originated from this IDE.

        Prevents double-processing when an IDE forwards another IDE's hook
        event (e.g. Cursor reading Claude Code hooks from ~/.claude/settings.json).
        """

    @abstractmethod
    def parse_hook_payload(self, raw_payload: dict) -> AIHookPayload:
        """Normalize a raw stdin payload into the canonical ``AIHookPayload``."""

    @abstractmethod
    def build_hook_response(self, decision: HookDecision) -> dict:
        """Translate a canonical ``HookDecision`` into the IDE-specific JSON.

        The result is what ``scan_command`` writes to stdout for the IDE to
        act on.
        """

    # --- session lifecycle (optional; sensible defaults) ---

    def build_session_payload(self, raw_payload: dict) -> AIHookPayload:
        """Build a session-start payload from the raw stdin payload.

        Default: a minimal payload tagged with this IDE's ``name``. IDEs
        that need to enrich with transcript/version info should override.
        """
        return AIHookPayload(ide_provider=self.name)

    def get_user_email(self) -> Optional[str]:
        """Best-effort read of the user's email from IDE-specific config.

        Default: None. Override if the IDE stores a usable account locally.
        """
        return None

    def get_session_context(self) -> tuple[dict, dict]:
        """Return ``(mcp_servers, enabled_plugins)`` for session-context reporting.

        Default: empty dicts (no plugin system, no discoverable MCP config).
        Override to surface MCP/plugin inventory.
        """
        return {}, {}
