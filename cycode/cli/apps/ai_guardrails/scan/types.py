"""Canonical event types and outcome enums for AI guardrails.

Per-IDE event-name mappings live on the IDE class (in
`cycode/cli/apps/ai_guardrails/ides/`); only the IDE-agnostic enums are kept
here.
"""

import sys

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from enum import Enum

    class StrEnum(str, Enum):
        def __str__(self) -> str:
            return self.value


class AiHookEventType(StrEnum):
    """Canonical, IDE-agnostic hook event types."""

    PROMPT = 'Prompt'
    FILE_READ = 'FileRead'
    MCP_EXECUTION = 'McpExecution'


class AIHookOutcome(StrEnum):
    """Outcome of an AI hook event evaluation."""

    ALLOWED = 'allowed'
    BLOCKED = 'blocked'
    WARNED = 'warned'


class BlockReason(StrEnum):
    """Categorical reason for blocking (sent to backend for tracking)."""

    SECRETS_IN_PROMPT = 'secrets_in_prompt'
    SECRETS_IN_FILE = 'secrets_in_file'
    SECRETS_IN_MCP_ARGS = 'secrets_in_mcp_args'
    SENSITIVE_PATH = 'sensitive_path'
    SCAN_FAILURE = 'scan_failure'
