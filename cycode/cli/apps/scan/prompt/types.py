"""Type definitions for AI guardrails."""

from enum import StrEnum


class AiHookEventType(StrEnum):
    """Canonical event types for AI guardrails.

    These are IDE-agnostic event types. Each IDE's specific event names
    are mapped to these canonical types using the mapping dictionaries below.
    """

    PROMPT = 'prompt'
    FILE_READ = 'file_read'
    MCP_EXECUTION = 'mcp_execution'


# IDE-specific event name mappings to canonical types
CURSOR_EVENT_MAPPING = {
    'beforeSubmitPrompt': AiHookEventType.PROMPT,
    'beforeReadFile': AiHookEventType.FILE_READ,
    'beforeMCPExecution': AiHookEventType.MCP_EXECUTION,
}


class AIHookOutcome(StrEnum):
    """Outcome of an AI hook event evaluation."""

    ALLOWED = 'allowed'
    BLOCKED = 'blocked'
    WARNED = 'warned'


class BlockReason(StrEnum):
    """Reason why an AI hook event was blocked.

    These are categorical reasons sent to the backend for tracking/analytics,
    separate from the detailed user-facing messages.
    """

    SECRETS_IN_PROMPT = 'secrets_in_prompt'
    SECRETS_IN_FILE = 'secrets_in_file'
    SECRETS_IN_MCP_ARGS = 'secrets_in_mcp_args'
    SENSITIVE_PATH = 'sensitive_path'
    SCAN_FAILURE = 'scan_failure'
