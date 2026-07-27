"""Shared constants and policy/mode enums for AI guardrails."""

from enum import Enum


class PolicyMode(str, Enum):
    """Policy enforcement mode for global mode and per-feature actions."""

    BLOCK = 'block'
    WARN = 'warn'


class GuardrailsMode(str, Enum):
    """Guardrails enforcement mode.

    Used both as the ai-guardrails install-command mode and as the per-event
    effective mode reported to the server (the ai_guardrails scan parameter's
    `mode` field)
    """

    REPORT = 'report'
    BLOCK = 'block'


# Base CLI commands invoked from installed hooks. IDE classes append --ide flags
# (and any other suffix) on top of these.
CYCODE_SCAN_PROMPT_COMMAND = 'cycode ai-guardrails scan'
CYCODE_SESSION_START_COMMAND = 'cycode ai-guardrails session-start'
