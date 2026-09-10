"""
Policy loading and configuration management for AI guardrails.

Operational knobs are loaded and merged in order (later overrides earlier):
1. Built-in defaults (consts.DEFAULT_POLICY)
2. Machine-wide config (admin/MDM-provisioned; see get_machine_policy_path)
3. User-level config (~/.cycode/ai-guardrails.yaml)
4. Repo-level config (<workspace>/.cycode/ai-guardrails.yaml)

Enforcement is not part of that merge: the platform resolves it and apply_platform_config
overlays it on top of the result (see scan/guardrail_config.py).
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

import yaml

from cycode.cli.apps.ai_guardrails.scan.consts import DEFAULT_POLICY, POLICY_FILE_NAME
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')

# A local policy file may only contribute operational knobs; enforcement comes from the
# platform. Read as a whitelist rather than a strip-list, so a key we forget to enumerate
# is ignored by default instead of silently weakening enforcement.
_LOCAL_POLICY_KEYS = ('version', 'fail_open', 'secrets')

# The sections the platform resolves. Only used when rewriting a user's file: keys an older
# CLI wrote there still read as enforcement to a human, so drop them on the way out.
_PLATFORM_OWNED_KEYS = ('mode', 'prompt', 'file_read', 'mcp')


def pick_local_knobs(config: dict, filename: str) -> dict:
    """Keep only the keys a local policy file is allowed to contribute."""
    ignored = [key for key in config if key not in _LOCAL_POLICY_KEYS]
    if ignored:
        logger.debug(
            'Ignoring non-knob keys in local policy file, %s',
            {'filename': filename, 'keys': ignored},
        )
    return {key: value for key, value in config.items() if key in _LOCAL_POLICY_KEYS}


def strip_platform_managed_keys(config: dict) -> dict:
    """Drop the enforcement sections a local file may carry (older CLIs wrote them)."""
    return {key: value for key, value in config.items() if key not in _PLATFORM_OWNED_KEYS}


def get_machine_policy_path() -> Path:
    """Machine-wide (admin/MDM-provisioned) policy path, by platform."""
    if sys.platform == 'darwin':
        return Path('/Library/Application Support/Cycode') / POLICY_FILE_NAME
    if sys.platform == 'win32':
        program_data = os.environ.get('PROGRAMDATA', 'C:\\ProgramData')
        return Path(program_data) / 'Cycode' / POLICY_FILE_NAME
    return Path('/etc/cycode') / POLICY_FILE_NAME


def deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dictionaries, with override taking precedence."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_yaml_file(path: Path) -> Optional[dict]:
    """Load a YAML or JSON config file."""
    if not path.exists():
        return None
    try:
        content = path.read_text(encoding='utf-8')
        if path.suffix in ('.yaml', '.yml'):
            return yaml.safe_load(content)
        return json.loads(content)
    except Exception:
        return None


def load_defaults() -> dict:
    """Load built-in defaults."""
    return DEFAULT_POLICY.copy()


def get_policy_value(policy: dict, *keys: str, default: Any = None) -> Any:
    """Get a nested value from the policy dict."""
    current = policy
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def load_policy(workspace_root: Optional[str] = None) -> dict:
    """
    Load policy by merging configs in order of precedence.

    Merge order: defaults <- machine <- user config <- repo config

    Args:
        workspace_root: Workspace root path for repo-level config lookup.
    """
    # Start with defaults
    policy = load_defaults()

    # Merge machine-wide config (admin/MDM-provisioned) - overrides defaults, below user/repo.
    machine_policy_path = get_machine_policy_path()
    machine_config = load_yaml_file(machine_policy_path)
    if machine_config:
        policy = deep_merge(policy, pick_local_knobs(machine_config, str(machine_policy_path)))

    # Merge user-level config (if exists)
    user_policy_path = Path.home() / '.cycode' / POLICY_FILE_NAME
    user_config = load_yaml_file(user_policy_path)
    if user_config:
        policy = deep_merge(policy, pick_local_knobs(user_config, str(user_policy_path)))

    # Merge repo-level config (if exists) - highest precedence
    if workspace_root:
        repo_policy_path = Path(workspace_root) / '.cycode' / POLICY_FILE_NAME
        repo_config = load_yaml_file(repo_policy_path)
        if repo_config:
            policy = deep_merge(policy, pick_local_knobs(repo_config, str(repo_policy_path)))

    return policy
