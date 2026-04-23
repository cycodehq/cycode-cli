"""Constants for AI guardrails hooks management.

Currently supports:
- Cursor
- Claude Code
- Codex
"""

import platform
from copy import deepcopy
from enum import Enum
from pathlib import Path
from typing import NamedTuple


class AIIDEType(str, Enum):
    """Supported AI IDE types."""

    CURSOR = 'cursor'
    CLAUDE_CODE = 'claude-code'
    CODEX = 'codex'


class PolicyMode(str, Enum):
    """Policy enforcement mode for global mode and per-feature actions."""

    BLOCK = 'block'
    WARN = 'warn'


class InstallMode(str, Enum):
    """Installation mode for ai-guardrails install command."""

    REPORT = 'report'
    BLOCK = 'block'


class IDEConfig(NamedTuple):
    """Configuration for an AI IDE."""

    name: str
    hooks_dir: Path
    repo_hooks_subdir: str  # Subdirectory in repo for hooks (e.g., '.cursor')
    hooks_file_name: str
    hook_events: list[str]  # List of supported hook event names for this IDE


def _get_cursor_hooks_dir() -> Path:
    """Get Cursor hooks directory based on platform."""
    if platform.system() == 'Darwin':
        return Path.home() / '.cursor'
    if platform.system() == 'Windows':
        return Path.home() / 'AppData' / 'Roaming' / 'Cursor'
    # Linux
    return Path.home() / '.config' / 'Cursor'


def _get_claude_code_hooks_dir() -> Path:
    """Get Claude Code hooks directory.

    Claude Code uses ~/.claude on all platforms.
    """
    return Path.home() / '.claude'


def _get_codex_hooks_dir() -> Path:
    """Get Codex hooks directory.

    Codex uses ~/.codex on all platforms.
    """
    return Path.home() / '.codex'


# IDE-specific configurations
IDE_CONFIGS: dict[AIIDEType, IDEConfig] = {
    AIIDEType.CURSOR: IDEConfig(
        name='Cursor',
        hooks_dir=_get_cursor_hooks_dir(),
        repo_hooks_subdir='.cursor',
        hooks_file_name='hooks.json',
        hook_events=['beforeSubmitPrompt', 'beforeReadFile', 'beforeMCPExecution'],
    ),
    AIIDEType.CLAUDE_CODE: IDEConfig(
        name='Claude Code',
        hooks_dir=_get_claude_code_hooks_dir(),
        repo_hooks_subdir='.claude',
        hooks_file_name='settings.json',
        hook_events=['UserPromptSubmit', 'PreToolUse:Read', 'PreToolUse:mcp'],
    ),
    AIIDEType.CODEX: IDEConfig(
        name='Codex',
        hooks_dir=_get_codex_hooks_dir(),
        repo_hooks_subdir='.codex',
        hooks_file_name='hooks.json',
        hook_events=['UserPromptSubmit', 'PreToolUse:Bash'],
    ),
}

# Default IDE
DEFAULT_IDE = AIIDEType.CURSOR

# Command used in hooks
CYCODE_SCAN_PROMPT_COMMAND = 'cycode ai-guardrails scan'
CYCODE_SESSION_START_COMMAND = 'cycode ai-guardrails session-start'


def _get_cursor_hooks_config(async_mode: bool = False) -> dict:
    """Get Cursor-specific hooks configuration."""
    config = IDE_CONFIGS[AIIDEType.CURSOR]
    command = f'{CYCODE_SCAN_PROMPT_COMMAND} &' if async_mode else CYCODE_SCAN_PROMPT_COMMAND
    hooks = {event: [{'command': command}] for event in config.hook_events}
    hooks['sessionStart'] = [{'command': f'{CYCODE_SESSION_START_COMMAND} --ide cursor'}]

    return {
        'version': 1,
        'hooks': hooks,
    }


def _get_claude_code_hooks_config(async_mode: bool = False) -> dict:
    """Get Claude Code-specific hooks configuration.

    Claude Code uses a different hook format with nested structure:
    - hooks are arrays of objects with 'hooks' containing command arrays
    - PreToolUse uses 'matcher' field to specify which tools to intercept
    """
    command = f'{CYCODE_SCAN_PROMPT_COMMAND} --ide claude-code'

    hook_entry = {'type': 'command', 'command': command}
    if async_mode:
        hook_entry['async'] = True
        hook_entry['timeout'] = 20

    return {
        'hooks': {
            'SessionStart': [
                {
                    'hooks': [{'type': 'command', 'command': f'{CYCODE_SESSION_START_COMMAND} --ide claude-code'}],
                }
            ],
            'UserPromptSubmit': [
                {
                    'hooks': [deepcopy(hook_entry)],
                }
            ],
            'PreToolUse': [
                {
                    'matcher': 'Read',
                    'hooks': [deepcopy(hook_entry)],
                },
                {
                    'matcher': 'mcp__.*',
                    'hooks': [deepcopy(hook_entry)],
                },
            ],
        },
    }


def _get_codex_hooks_config(async_mode: bool = False) -> dict:
    """Get Codex-specific hooks configuration.

    Codex uses the same nested hook-entry format as Claude Code:
    - events are keyed by name
    - each entry has an optional 'matcher' (regex on tool name / start source)
      and a 'hooks' array with {type, command, ...}

    Codex only supports intercepting Bash for PreToolUse today; MCP and file
    reads are not exposed to hooks.
    """
    command = f'{CYCODE_SCAN_PROMPT_COMMAND} --ide {AIIDEType.CODEX.value}'
    session_start_command = f'{CYCODE_SESSION_START_COMMAND} --ide {AIIDEType.CODEX.value}'

    hook_entry = {'type': 'command', 'command': command}
    if async_mode:
        hook_entry['async'] = True
        hook_entry['timeout'] = 20

    return {
        'hooks': {
            'SessionStart': [
                {
                    'matcher': 'startup',
                    'hooks': [{'type': 'command', 'command': session_start_command}],
                }
            ],
            'UserPromptSubmit': [
                {
                    'hooks': [deepcopy(hook_entry)],
                }
            ],
            'PreToolUse': [
                {
                    'matcher': 'Bash',
                    'hooks': [deepcopy(hook_entry)],
                },
            ],
        },
    }


def get_hooks_config(ide: AIIDEType, async_mode: bool = False) -> dict:
    """Get the hooks configuration for a specific IDE.

    Args:
        ide: The AI IDE type
        async_mode: If True, hooks run asynchronously (non-blocking)

    Returns:
        Dict with hooks configuration for the specified IDE
    """
    if ide == AIIDEType.CLAUDE_CODE:
        return _get_claude_code_hooks_config(async_mode=async_mode)
    if ide == AIIDEType.CODEX:
        return _get_codex_hooks_config(async_mode=async_mode)
    return _get_cursor_hooks_config(async_mode=async_mode)
