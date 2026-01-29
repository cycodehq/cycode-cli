"""Constants for AI guardrails hooks management.

Currently supports:
- Cursor

To add a new IDE (e.g., Claude Code):
1. Add new value to AIIDEType enum
2. Create _get_<ide>_hooks_dir() function with platform-specific paths
3. Add entry to IDE_CONFIGS dict with IDE-specific hook event names
4. Unhide --ide option in commands (install, uninstall, status)
"""

import platform
from enum import Enum
from pathlib import Path
from typing import NamedTuple


class AIIDEType(str, Enum):
    """Supported AI IDE types."""

    CURSOR = 'cursor'


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


# IDE-specific configurations
IDE_CONFIGS: dict[AIIDEType, IDEConfig] = {
    AIIDEType.CURSOR: IDEConfig(
        name='Cursor',
        hooks_dir=_get_cursor_hooks_dir(),
        repo_hooks_subdir='.cursor',
        hooks_file_name='hooks.json',
        hook_events=['beforeSubmitPrompt', 'beforeReadFile', 'beforeMCPExecution'],
    ),
}

# Default IDE
DEFAULT_IDE = AIIDEType.CURSOR

# Command used in hooks
CYCODE_SCAN_PROMPT_COMMAND = 'cycode ai-guardrails scan'


def get_hooks_config(ide: AIIDEType) -> dict:
    """Get the hooks configuration for a specific IDE.

    Args:
        ide: The AI IDE type

    Returns:
        Dict with hooks configuration for the specified IDE
    """
    config = IDE_CONFIGS[ide]
    hooks = {event: [{'command': CYCODE_SCAN_PROMPT_COMMAND}] for event in config.hook_events}

    return {
        'version': 1,
        'hooks': hooks,
    }
