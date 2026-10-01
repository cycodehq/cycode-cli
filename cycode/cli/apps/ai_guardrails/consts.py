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


class GuardrailCellMode(str, Enum):
    """A guardrail x agent cell in the platform-resolved matrix.

    Separate from GuardrailsMode because Off is a platform-only state: it is not an
    install `--mode` choice, and an off guardrail reports no mode to the server.
    """

    OFF = 'off'
    REPORT = GuardrailsMode.REPORT.value
    BLOCK = GuardrailsMode.BLOCK.value


class McpServerEnforceOn(str, Enum):
    """Which MCP servers the unauthorized MCP server guardrail enforces on (its `enforce_on` setting)."""

    UNAUTHORIZED = 'unauthorized'  # only servers explicitly marked Unauthorized
    NOT_AUTHORIZED = 'not_authorized'  # strict: anything that isn't Authorized, servers ASM hasn't seen included


# Base CLI commands invoked from installed hooks. IDE classes append --ide flags
# (and any other suffix) on top of these.
CYCODE_SCAN_PROMPT_COMMAND = 'cycode ai-guardrails scan'
CYCODE_SESSION_START_COMMAND = 'cycode ai-guardrails session-start'
