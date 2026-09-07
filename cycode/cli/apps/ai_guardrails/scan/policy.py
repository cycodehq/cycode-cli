"""
Policy loading and configuration management for AI guardrails.

Policies are loaded and merged in order (later overrides earlier):
1. Built-in defaults (consts.DEFAULT_POLICY)
2. Machine-wide config (admin/MDM-provisioned; see get_machine_policy_path)
3. User-level config (~/.cycode/ai-guardrails.yaml)
4. Repo-level config (<workspace>/.cycode/ai-guardrails.yaml)
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

# Enforcement policy is platform-owned (fetched at session-start and cached): local files may
# only carry operational knobs (secrets.timeout_ms/max_bytes, fail_open). Every key here is
# either overwritten from the platform config on each scan or no longer read at all (`mode`),
# so a local value would be silently dead.
_PLATFORM_MANAGED_TOP_KEYS = ('mode',)
_PLATFORM_MANAGED_FEATURE_KEYS = {
    'prompt': ('enabled', 'action'),
    'file_read': ('enabled', 'action', 'path_action', 'scan_content', 'deny_globs'),
    'mcp': ('enabled', 'action'),
}


def strip_platform_managed_keys(config: dict, filename: str) -> dict:
    """Drop enforcement keys a local file may carry (older CLIs wrote them)."""
    stripped = [key for key in _PLATFORM_MANAGED_TOP_KEYS if config.pop(key, None) is not None]

    for feature, keys in _PLATFORM_MANAGED_FEATURE_KEYS.items():
        feature_config = config.get(feature)
        if not isinstance(feature_config, dict):
            continue
        stripped.extend(f'{feature}.{key}' for key in keys if feature_config.pop(key, None) is not None)

    if stripped:
        logger.debug(
            'Ignoring platform-managed keys in local policy file, %s',
            {'filename': filename, 'keys': stripped},
        )
    return config


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
        policy = deep_merge(policy, strip_platform_managed_keys(machine_config, str(machine_policy_path)))

    # Merge user-level config (if exists)
    user_policy_path = Path.home() / '.cycode' / POLICY_FILE_NAME
    user_config = load_yaml_file(user_policy_path)
    if user_config:
        policy = deep_merge(policy, strip_platform_managed_keys(user_config, str(user_policy_path)))

    # Merge repo-level config (if exists) - highest precedence
    if workspace_root:
        repo_policy_path = Path(workspace_root) / '.cycode' / POLICY_FILE_NAME
        repo_config = load_yaml_file(repo_policy_path)
        if repo_config:
            policy = deep_merge(policy, strip_platform_managed_keys(repo_config, str(repo_policy_path)))

    return policy
