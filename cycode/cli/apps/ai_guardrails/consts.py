"""Shared constants and policy/mode enums for AI guardrails."""

from enum import Enum


class PolicyMode(str, Enum):
    """Policy enforcement mode for global mode and per-feature actions."""

    BLOCK = 'block'
    WARN = 'warn'


class InstallMode(str, Enum):
    """Installation mode for ai-guardrails install command."""

    REPORT = 'report'
    BLOCK = 'block'


# Base CLI commands invoked from installed hooks. IDE classes append --ide flags
# (and any other suffix) on top of these.
CYCODE_SCAN_PROMPT_COMMAND = 'cycode ai-guardrails scan'
CYCODE_SESSION_START_COMMAND = 'cycode ai-guardrails session-start'
