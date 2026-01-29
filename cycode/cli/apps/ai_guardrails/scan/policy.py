"""
Policy loading and configuration management for AI guardrails.

Policies are loaded and merged in order (later overrides earlier):
1. Built-in defaults (consts.DEFAULT_POLICY)
2. User-level config (~/.cycode/ai-guardrails.yaml)
3. Repo-level config (<workspace>/.cycode/ai-guardrails.yaml)
"""

import json
from pathlib import Path
from typing import Any, Optional

import yaml

from cycode.cli.apps.ai_guardrails.scan.consts import DEFAULT_POLICY, POLICY_FILE_NAME


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

    Merge order: defaults <- user config <- repo config

    Args:
        workspace_root: Workspace root path for repo-level config lookup.
    """
    # Start with defaults
    policy = load_defaults()

    # Merge user-level config (if exists)
    user_policy_path = Path.home() / '.cycode' / POLICY_FILE_NAME
    user_config = load_yaml_file(user_policy_path)
    if user_config:
        policy = deep_merge(policy, user_config)

    # Merge repo-level config (if exists) - highest precedence
    if workspace_root:
        repo_policy_path = Path(workspace_root) / '.cycode' / POLICY_FILE_NAME
        repo_config = load_yaml_file(repo_policy_path)
        if repo_config:
            policy = deep_merge(policy, repo_config)

    return policy
