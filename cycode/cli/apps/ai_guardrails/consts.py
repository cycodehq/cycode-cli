"""Constants for AI guardrails hooks management.

Currently supports:
- Cursor
- Claude Code
"""

import platform
from enum import Enum
from pathlib import Path
from typing import NamedTuple


class AIIDEType(str, Enum):
    """Supported AI IDE types."""

    CURSOR = 'cursor'
    CLAUDE_CODE = 'claude-code'


class PolicyMode(str, Enum):
    """Policy enforcement mode for global mode and per-feature actions."""

    BLOCK = 'block'
    WARN = 'warn'


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
}

# Default IDE
DEFAULT_IDE = AIIDEType.CURSOR

# Command used in hooks
CYCODE_SCAN_PROMPT_COMMAND = 'cycode ai-guardrails scan'


def _get_cursor_hooks_config() -> dict:
    """Get Cursor-specific hooks configuration."""
    config = IDE_CONFIGS[AIIDEType.CURSOR]
    hooks = {event: [{'command': CYCODE_SCAN_PROMPT_COMMAND}] for event in config.hook_events}

    return {
        'version': 1,
        'hooks': hooks,
    }


def _get_claude_code_hooks_config() -> dict:
    """Get Claude Code-specific hooks configuration.

    Claude Code uses a different hook format with nested structure:
    - hooks are arrays of objects with 'hooks' containing command arrays
    - PreToolUse uses 'matcher' field to specify which tools to intercept
    """
    command = f'{CYCODE_SCAN_PROMPT_COMMAND} --ide claude-code'

    return {
        'hooks': {
            'UserPromptSubmit': [
                {
                    'hooks': [{'type': 'command', 'command': command}],
                }
            ],
            'PreToolUse': [
                {
                    'matcher': 'Read',
                    'hooks': [{'type': 'command', 'command': command}],
                },
                {
                    'matcher': 'mcp__.*',
                    'hooks': [{'type': 'command', 'command': command}],
                },
            ],
        },
    }


def get_hooks_config(ide: AIIDEType) -> dict:
    """Get the hooks configuration for a specific IDE.

    Args:
        ide: The AI IDE type

    Returns:
        Dict with hooks configuration for the specified IDE
    """
    if ide == AIIDEType.CLAUDE_CODE:
        return _get_claude_code_hooks_config()
    return _get_cursor_hooks_config()
