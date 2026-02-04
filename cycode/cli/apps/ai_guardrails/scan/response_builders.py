"""
Response builders for different AI IDE hooks.

Each IDE has its own response format for hooks. This module provides
an abstract interface and concrete implementations for each supported IDE.
"""

from abc import ABC, abstractmethod

from cycode.cli.apps.ai_guardrails.consts import AIIDEType


class IDEResponseBuilder(ABC):
    """Abstract base class for IDE-specific response builders."""

    @abstractmethod
    def allow_permission(self) -> dict:
        """Build response to allow file read or MCP execution."""

    @abstractmethod
    def deny_permission(self, user_message: str, agent_message: str) -> dict:
        """Build response to deny file read or MCP execution."""

    @abstractmethod
    def ask_permission(self, user_message: str, agent_message: str) -> dict:
        """Build response to ask user for permission (warn mode)."""

    @abstractmethod
    def allow_prompt(self) -> dict:
        """Build response to allow prompt submission."""

    @abstractmethod
    def deny_prompt(self, user_message: str) -> dict:
        """Build response to deny prompt submission."""


class CursorResponseBuilder(IDEResponseBuilder):
    """Response builder for Cursor IDE hooks.

    Cursor hook response formats:
    - beforeSubmitPrompt: {"continue": bool, "user_message": str}
    - beforeReadFile: {"permission": str, "user_message": str, "agent_message": str}
    - beforeMCPExecution: {"permission": str, "user_message": str, "agent_message": str}
    """

    def allow_permission(self) -> dict:
        """Allow file read or MCP execution."""
        return {'permission': 'allow'}

    def deny_permission(self, user_message: str, agent_message: str) -> dict:
        """Deny file read or MCP execution."""
        return {'permission': 'deny', 'user_message': user_message, 'agent_message': agent_message}

    def ask_permission(self, user_message: str, agent_message: str) -> dict:
        """Ask user for permission (warn mode)."""
        return {'permission': 'ask', 'user_message': user_message, 'agent_message': agent_message}

    def allow_prompt(self) -> dict:
        """Allow prompt submission."""
        return {'continue': True}

    def deny_prompt(self, user_message: str) -> dict:
        """Deny prompt submission."""
        return {'continue': False, 'user_message': user_message}


class ClaudeCodeResponseBuilder(IDEResponseBuilder):
    """Response builder for Claude Code IDE hooks.

    Claude Code hook response formats:
    - UserPromptSubmit: {} for allow, {"decision": "block", "reason": str} for deny
    - PreToolUse: hookSpecificOutput with permissionDecision (allow/deny/ask)
    """

    def allow_permission(self) -> dict:
        """Allow file read or MCP execution."""
        return {
            'hookSpecificOutput': {
                'hookEventName': 'PreToolUse',
                'permissionDecision': 'allow',
            }
        }

    def deny_permission(self, user_message: str, agent_message: str) -> dict:
        """Deny file read or MCP execution."""
        return {
            'hookSpecificOutput': {
                'hookEventName': 'PreToolUse',
                'permissionDecision': 'deny',
                'permissionDecisionReason': user_message,
            }
        }

    def ask_permission(self, user_message: str, agent_message: str) -> dict:
        """Ask user for permission (warn mode)."""
        return {
            'hookSpecificOutput': {
                'hookEventName': 'PreToolUse',
                'permissionDecision': 'ask',
                'permissionDecisionReason': user_message,
            }
        }

    def allow_prompt(self) -> dict:
        """Allow prompt submission (empty response means allow)."""
        return {}

    def deny_prompt(self, user_message: str) -> dict:
        """Deny prompt submission."""
        return {'decision': 'block', 'reason': user_message}


# Registry of response builders by IDE type
_RESPONSE_BUILDERS: dict[str, IDEResponseBuilder] = {
    AIIDEType.CURSOR: CursorResponseBuilder(),
    AIIDEType.CLAUDE_CODE: ClaudeCodeResponseBuilder(),
}


def get_response_builder(ide: str = AIIDEType.CURSOR.value) -> IDEResponseBuilder:
    """Get the response builder for a specific IDE.

    Args:
        ide: The IDE name (e.g., 'cursor', 'claude-code') or AIIDEType enum

    Returns:
        IDEResponseBuilder instance for the specified IDE

    Raises:
        ValueError: If the IDE is not supported
    """
    builder = _RESPONSE_BUILDERS.get(ide.lower())
    if not builder:
        raise ValueError(f'Unsupported IDE: {ide}. Supported IDEs: {list(_RESPONSE_BUILDERS.keys())}')
    return builder
