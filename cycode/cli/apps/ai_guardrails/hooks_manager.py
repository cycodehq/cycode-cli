"""Hooks manager for AI guardrails.

Generic install/uninstall/status logic. All IDE-specific concerns (settings
paths, hooks template shape) live on the `IDE` instance; this module is
agent-agnostic.
"""

import copy
import json
from pathlib import Path
from typing import Optional

import yaml

from cycode.cli.apps.ai_guardrails.consts import PolicyMode
from cycode.cli.apps.ai_guardrails.ides.base import IDE
from cycode.cli.apps.ai_guardrails.scan.consts import DEFAULT_POLICY, POLICY_FILE_NAME
from cycode.logger import get_logger

logger = get_logger('AI Guardrails Hooks')


_CYCODE_COMMAND_MARKERS = ('cycode ai-guardrails',)

# Command-carrying fields of a flat hook entry. Copilot entries use per-OS
# `bash`/`powershell` fields instead of `command`.
_COMMAND_FIELDS = ('command', 'bash', 'powershell')


def _is_cycode_command(command: str) -> bool:
    return any(marker in command for marker in _CYCODE_COMMAND_MARKERS)


def _has_cycode_command_field(entry: dict) -> bool:
    return any(_is_cycode_command(entry.get(field, '')) for field in _COMMAND_FIELDS)


def is_cycode_hook_entry(entry: dict) -> bool:
    """True if any hook inside ``entry`` is owned by Cycode."""
    if _has_cycode_command_field(entry):
        return True

    for hook in entry.get('hooks', []):
        if isinstance(hook, dict) and _is_cycode_command(hook.get('command', '')):
            return True

    return False


def _strip_cycode_from_entry(entry: dict) -> Optional[dict]:
    """Remove Cycode hooks from ``entry`` and return the remainder.

    Returns ``None`` when nothing useful remains (Cursor-flat Cycode entry, or
    every nested hook was Cycode). Non-Cycode hooks co-located in the same
    entry are preserved.
    """
    # Cursor/Copilot format: the entry itself IS a single hook command.
    if 'hooks' not in entry and any(field in entry for field in _COMMAND_FIELDS):
        return None if _has_cycode_command_field(entry) else entry

    # Claude Code / Codex format: nested `hooks` list inside the entry.
    nested = entry.get('hooks')
    if isinstance(nested, list):
        kept = [h for h in nested if not (isinstance(h, dict) and _is_cycode_command(h.get('command', '')))]
        if not kept:
            return None
        if len(kept) == len(nested):
            return entry  # nothing Cycode-shaped inside; preserve identity
        return {**entry, 'hooks': kept}

    # Entry has neither shape we recognize — leave it alone defensively.
    return entry


def _load_hooks_file(hooks_path: Path) -> Optional[dict]:
    if not hooks_path.exists():
        return None
    try:
        return json.loads(hooks_path.read_text(encoding='utf-8'))
    except Exception as e:
        logger.debug('Failed to load hooks file', exc_info=e)
        return None


def _save_hooks_file(hooks_path: Path, hooks_config: dict) -> bool:
    try:
        hooks_path.parent.mkdir(parents=True, exist_ok=True)
        hooks_path.write_text(json.dumps(hooks_config, indent=2), encoding='utf-8')
        return True
    except Exception as e:
        logger.error('Failed to save hooks file', exc_info=e)
        return False


def _load_policy_dict(policy_path: Path) -> dict:
    if not policy_path.exists():
        return copy.deepcopy(DEFAULT_POLICY)
    try:
        existing = yaml.safe_load(policy_path.read_text(encoding='utf-8')) or {}
    except Exception:
        existing = {}
    return {**copy.deepcopy(DEFAULT_POLICY), **existing}


def create_policy_file(scope: str, mode: PolicyMode, repo_path: Optional[Path] = None) -> tuple[bool, str]:
    """Create or update the ai-guardrails.yaml policy file.

    If the file already exists, only the mode field is updated; otherwise a new
    file is created from the default policy.
    """
    config_dir = repo_path / '.cycode' if scope == 'repo' and repo_path else Path.home() / '.cycode'
    policy_path = config_dir / POLICY_FILE_NAME

    policy = _load_policy_dict(policy_path)
    policy['mode'] = mode.value

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(yaml.dump(policy, default_flow_style=False, sort_keys=False), encoding='utf-8')
        return True, f'AI guardrails policy ({mode.value} mode) set: {policy_path}'
    except Exception as e:
        logger.error('Failed to create policy file', exc_info=e)
        return False, f'Failed to create policy file: {policy_path}'


def install_hooks(
    ide: IDE,
    scope: str = 'user',
    repo_path: Optional[Path] = None,
    report_mode: bool = False,
) -> tuple[bool, str]:
    """Install Cycode AI guardrails hooks for ``ide``."""
    hooks_path = ide.settings_path(scope, repo_path)

    existing = _load_hooks_file(hooks_path) or {'version': 1, 'hooks': {}}
    existing.setdefault('version', 1)
    existing.setdefault('hooks', {})

    rendered = ide.render_hooks_config(async_mode=report_mode)

    for event, entries in rendered['hooks'].items():
        existing['hooks'].setdefault(event, [])
        existing['hooks'][event] = [
            stripped for e in existing['hooks'][event] if (stripped := _strip_cycode_from_entry(e)) is not None
        ]
        for entry in entries:
            existing['hooks'][event].append(entry)

    if not _save_hooks_file(hooks_path, existing):
        return False, f'Failed to install hooks to {hooks_path}'

    message = f'AI guardrails hooks installed: {hooks_path}'

    # IDE-specific extras (e.g. Codex enables a TOML feature flag).
    extra_ok, extra_message = ide.post_install(scope, repo_path)
    if not extra_ok:
        return False, extra_message
    if extra_message:
        message = f'{message}\n  {extra_message}'

    return True, message


def _strip_cycode_entries(existing: dict) -> bool:
    """Mutate ``existing`` to drop Cycode hooks (surgically). Return True if anything changed."""
    modified = False
    for event in list(existing.get('hooks', {}).keys()):
        before = existing['hooks'][event]
        after: list = []
        for e in before:
            stripped = _strip_cycode_from_entry(e)
            if stripped is None:
                modified = True
                continue
            if stripped is not e:
                modified = True
            after.append(stripped)
        if not after:
            del existing['hooks'][event]
        else:
            existing['hooks'][event] = after
    return modified


def _persist_uninstall(hooks_path: Path, existing: dict, modified: bool) -> tuple[bool, str]:
    """Apply the uninstall result to disk and return ``(success, message)``."""
    if not modified:
        return True, 'No Cycode hooks found to remove'
    if not existing.get('hooks'):
        try:
            hooks_path.unlink()
        except Exception as e:
            logger.debug('Failed to delete hooks file', exc_info=e)
            return False, f'Failed to remove hooks file: {hooks_path}'
        return True, f'Removed hooks file: {hooks_path}'
    if not _save_hooks_file(hooks_path, existing):
        return False, f'Failed to update hooks file: {hooks_path}'
    return True, f'Cycode hooks removed from: {hooks_path}'


def uninstall_hooks(ide: IDE, scope: str = 'user', repo_path: Optional[Path] = None) -> tuple[bool, str]:
    """Remove Cycode AI guardrails hooks for ``ide``."""
    hooks_path = ide.settings_path(scope, repo_path)

    existing = _load_hooks_file(hooks_path)
    if existing is None:
        return True, f'No hooks file found at {hooks_path}'

    modified = _strip_cycode_entries(existing)
    file_ok, message = _persist_uninstall(hooks_path, existing, modified)
    if not file_ok:
        return False, message

    extra_ok, extra_message = ide.post_uninstall(scope, repo_path)
    if not extra_ok:
        return False, extra_message
    if extra_message:
        message = f'{message}\n  {extra_message}'
    return True, message


def get_hooks_status(ide: IDE, scope: str = 'user', repo_path: Optional[Path] = None) -> dict:
    """Return installation status of Cycode hooks for ``ide``."""
    hooks_path = ide.settings_path(scope, repo_path)

    status: dict = {
        'scope': scope,
        'ide': ide.name,
        'ide_name': ide.display_name,
        'hooks_path': str(hooks_path),
        'file_exists': hooks_path.exists(),
        'cycode_installed': False,
        'hooks': {},
    }

    existing = _load_hooks_file(hooks_path)
    if existing is None:
        return status

    has_cycode_hooks = False
    for event in ide.hook_events:
        # '<event>:<matcher>' filters entries to a specific tool/matcher.
        if ':' in event:
            actual_event, matcher_prefix = event.split(':', 1)
            all_entries = existing.get('hooks', {}).get(actual_event, [])
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
