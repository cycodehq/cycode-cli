"""
Hooks manager for AI guardrails.

Handles installation, removal, and status checking of AI IDE hooks.
Supports multiple IDEs: Cursor, Claude Code (future).
"""

import json
from pathlib import Path
from typing import Optional

from cycode.cli.apps.ai_guardrails.consts import (
    CYCODE_SCAN_PROMPT_COMMAND,
    DEFAULT_IDE,
    IDE_CONFIGS,
    AIIDEType,
    get_hooks_config,
)
from cycode.logger import get_logger

logger = get_logger('AI Guardrails Hooks')


def get_hooks_path(scope: str, repo_path: Optional[Path] = None, ide: AIIDEType = DEFAULT_IDE) -> Path:
    """Get the hooks.json path for the given scope and IDE.

    Args:
        scope: 'user' for user-level hooks, 'repo' for repository-level hooks
        repo_path: Repository path (required if scope is 'repo')
        ide: The AI IDE type (default: Cursor)
    """
    config = IDE_CONFIGS[ide]
    if scope == 'repo' and repo_path:
        return repo_path / config.repo_hooks_subdir / config.hooks_file_name
    return config.hooks_dir / config.hooks_file_name


def load_hooks_file(hooks_path: Path) -> Optional[dict]:
    """Load existing hooks.json file."""
    if not hooks_path.exists():
        return None
    try:
        content = hooks_path.read_text(encoding='utf-8')
        return json.loads(content)
    except Exception as e:
        logger.debug('Failed to load hooks file', exc_info=e)
        return None


def save_hooks_file(hooks_path: Path, hooks_config: dict) -> bool:
    """Save hooks.json file."""
    try:
        hooks_path.parent.mkdir(parents=True, exist_ok=True)
        hooks_path.write_text(json.dumps(hooks_config, indent=2), encoding='utf-8')
        return True
    except Exception as e:
        logger.error('Failed to save hooks file', exc_info=e)
        return False


def is_cycode_hook_entry(entry: dict) -> bool:
    """Check if a hook entry is from cycode-cli.

    Handles both Cursor format (flat) and Claude Code format (nested).

    Cursor format: {"command": "cycode ai-guardrails scan"}
    Claude Code format: {"hooks": [{"type": "command", "command": "cycode ai-guardrails scan --ide claude-code"}]}
    """
    # Check Cursor format (flat command)
    command = entry.get('command', '')
    if CYCODE_SCAN_PROMPT_COMMAND in command:
        return True

    # Check Claude Code format (nested hooks array)
    hooks = entry.get('hooks', [])
    for hook in hooks:
        if isinstance(hook, dict):
            hook_command = hook.get('command', '')
            if CYCODE_SCAN_PROMPT_COMMAND in hook_command:
                return True

    return False


def install_hooks(
    scope: str = 'user', repo_path: Optional[Path] = None, ide: AIIDEType = DEFAULT_IDE
) -> tuple[bool, str]:
    """
    Install Cycode AI guardrails hooks.

    Args:
        scope: 'user' for user-level hooks, 'repo' for repository-level hooks
        repo_path: Repository path (required if scope is 'repo')
        ide: The AI IDE type (default: Cursor)

    Returns:
        Tuple of (success, message)
    """
    hooks_path = get_hooks_path(scope, repo_path, ide)

    # Load existing hooks or create new
    existing = load_hooks_file(hooks_path) or {'version': 1, 'hooks': {}}
    existing.setdefault('version', 1)
    existing.setdefault('hooks', {})

    # Get IDE-specific hooks configuration
    hooks_config = get_hooks_config(ide)

    # Add/update Cycode hooks
    for event, entries in hooks_config['hooks'].items():
        existing['hooks'].setdefault(event, [])

        # Remove any existing Cycode entries for this event
        existing['hooks'][event] = [e for e in existing['hooks'][event] if not is_cycode_hook_entry(e)]

        # Add new Cycode entries
        for entry in entries:
            existing['hooks'][event].append(entry)

    # Save
    if save_hooks_file(hooks_path, existing):
        return True, f'AI guardrails hooks installed: {hooks_path}'
    return False, f'Failed to install hooks to {hooks_path}'


def uninstall_hooks(
    scope: str = 'user', repo_path: Optional[Path] = None, ide: AIIDEType = DEFAULT_IDE
) -> tuple[bool, str]:
    """
    Remove Cycode AI guardrails hooks.

    Args:
        scope: 'user' for user-level hooks, 'repo' for repository-level hooks
        repo_path: Repository path (required if scope is 'repo')
        ide: The AI IDE type (default: Cursor)

    Returns:
        Tuple of (success, message)
    """
    hooks_path = get_hooks_path(scope, repo_path, ide)

    existing = load_hooks_file(hooks_path)
    if existing is None:
        return True, f'No hooks file found at {hooks_path}'

    # Remove Cycode entries from all events
    modified = False
    for event in list(existing.get('hooks', {}).keys()):
        original_count = len(existing['hooks'][event])
        existing['hooks'][event] = [e for e in existing['hooks'][event] if not is_cycode_hook_entry(e)]
        if len(existing['hooks'][event]) != original_count:
            modified = True
        # Remove empty event lists
        if not existing['hooks'][event]:
            del existing['hooks'][event]

    if not modified:
        return True, 'No Cycode hooks found to remove'

    # Save or delete if empty
    if not existing.get('hooks'):
        try:
            hooks_path.unlink()
            return True, f'Removed hooks file: {hooks_path}'
        except Exception as e:
            logger.debug('Failed to delete hooks file', exc_info=e)
            return False, f'Failed to remove hooks file: {hooks_path}'

    if save_hooks_file(hooks_path, existing):
        return True, f'Cycode hooks removed from: {hooks_path}'
    return False, f'Failed to update hooks file: {hooks_path}'


def get_hooks_status(scope: str = 'user', repo_path: Optional[Path] = None, ide: AIIDEType = DEFAULT_IDE) -> dict:
    """
    Get the status of AI guardrails hooks.

    Args:
        scope: 'user' for user-level hooks, 'repo' for repository-level hooks
        repo_path: Repository path (required if scope is 'repo')
        ide: The AI IDE type (default: Cursor)

    Returns:
        Dict with status information
    """
    hooks_path = get_hooks_path(scope, repo_path, ide)

    status = {
        'scope': scope,
        'ide': ide.value,
        'ide_name': IDE_CONFIGS[ide].name,
        'hooks_path': str(hooks_path),
        'file_exists': hooks_path.exists(),
        'cycode_installed': False,
        'hooks': {},
    }

    existing = load_hooks_file(hooks_path)
    if existing is None:
        return status

    # Check each hook event for this IDE
    ide_config = IDE_CONFIGS[ide]
    has_cycode_hooks = False
    for event in ide_config.hook_events:
        # Handle event:matcher format
        if ':' in event:
            actual_event, matcher_prefix = event.split(':', 1)
            all_entries = existing.get('hooks', {}).get(actual_event, [])
            # Filter entries by matcher
            entries = [e for e in all_entries if e.get('matcher', '').startswith(matcher_prefix)]
        else:
            entries = existing.get('hooks', {}).get(event, [])

        cycode_entries = [e for e in entries if is_cycode_hook_entry(e)]
        if cycode_entries:
            has_cycode_hooks = True
        status['hooks'][event] = {
            'total_entries': len(entries),
            'cycode_entries': len(cycode_entries),
            'enabled': len(cycode_entries) > 0,
        }

    status['cycode_installed'] = has_cycode_hooks

    return status
