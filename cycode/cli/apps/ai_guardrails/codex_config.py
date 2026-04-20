"""Codex CLI config.toml management for AI guardrails.

Codex requires `[features] codex_hooks = true` in its `config.toml` for hook
scripts to be invoked. This module merges that flag into the user-scope
(`~/.codex/config.toml`) or repo-scope (`<repo>/.codex/config.toml`) file while
preserving any existing keys.
"""

import sys
from pathlib import Path
from typing import Optional

import tomli_w

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - py<3.11 fallback
    import tomli as tomllib

from cycode.logger import get_logger

logger = get_logger('AI Guardrails Codex Config')

CODEX_CONFIG_FILE_NAME = 'config.toml'
CODEX_CONFIG_DIR_NAME = '.codex'


def get_codex_config_path(scope: str, repo_path: Optional[Path] = None) -> Path:
    """Get the Codex config.toml path for the given scope."""
    if scope == 'repo' and repo_path:
        return repo_path / CODEX_CONFIG_DIR_NAME / CODEX_CONFIG_FILE_NAME
    return Path.home() / CODEX_CONFIG_DIR_NAME / CODEX_CONFIG_FILE_NAME


def enable_codex_hooks_feature(scope: str = 'user', repo_path: Optional[Path] = None) -> tuple[bool, str]:
    """Ensure `[features] codex_hooks = true` is set in Codex's config.toml.

    Preserves existing keys. Creates the file (and parent dir) if missing.

    Returns:
        Tuple of (success, message).
    """
    config_path = get_codex_config_path(scope, repo_path)

    config: dict = {}
    if config_path.exists():
        try:
            with config_path.open('rb') as f:
                config = tomllib.load(f)
        except Exception as e:
            logger.error('Failed to parse Codex config.toml', exc_info=e)
            return False, f'Failed to parse existing Codex config at {config_path}'

    features = config.get('features')
    if not isinstance(features, dict):
        features = {}
    features['codex_hooks'] = True
    config['features'] = features

    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with config_path.open('wb') as f:
            tomli_w.dump(config, f)
        return True, f'Enabled codex_hooks in {config_path}'
    except Exception as e:
        logger.error('Failed to write Codex config.toml', exc_info=e)
        return False, f'Failed to write Codex config at {config_path}'
