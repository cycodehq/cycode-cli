"""Reader for ~/.claude.json configuration file.

Extracts user email from the Claude Code global config file
for use in AI guardrails scan enrichment.
"""

import json
from pathlib import Path
from typing import Optional

from cycode.logger import get_logger

logger = get_logger('AI Guardrails Claude Config')

_CLAUDE_CONFIG_PATH = Path.home() / '.claude.json'
_CLAUDE_SETTINGS_PATH = Path.home() / '.claude' / 'settings.json'


def load_claude_config(config_path: Optional[Path] = None) -> Optional[dict]:
    """Load and parse ~/.claude.json.

    Args:
        config_path: Override path for testing. Defaults to ~/.claude.json.

    Returns:
        Parsed dict or None if file is missing or invalid.
    """
    path = config_path or _CLAUDE_CONFIG_PATH
    if not path.exists():
        logger.debug('Claude config file not found', extra={'path': str(path)})
        return None
    try:
        content = path.read_text(encoding='utf-8')
        return json.loads(content)
    except Exception as e:
        logger.debug('Failed to load Claude config file', exc_info=e)
        return None


def get_user_email(config: dict) -> Optional[str]:
    """Extract user email from Claude config.

    Reads oauthAccount.emailAddress from the config dict.
    """
    return config.get('oauthAccount', {}).get('emailAddress')


def get_mcp_servers(config: dict) -> Optional[dict]:
    """Extract MCP servers from Claude config.

    Reads mcpServers from the config dict.
    """
    return config.get('mcpServers')


def load_claude_settings(settings_path: Optional[Path] = None) -> Optional[dict]:
    """Load and parse ~/.claude/settings.json.

    Args:
        settings_path: Override path for testing. Defaults to ~/.claude/settings.json.

    Returns:
        Parsed dict or None if file is missing or invalid.
    """
    path = settings_path or _CLAUDE_SETTINGS_PATH
    if not path.exists():
        logger.debug('Claude settings file not found', extra={'path': str(path)})
        return None
    try:
        content = path.read_text(encoding='utf-8')
        return json.loads(content)
    except Exception as e:
        logger.debug('Failed to load Claude settings file', exc_info=e)
        return None


def get_enabled_plugins(settings: dict) -> Optional[dict]:
    """Extract enabled plugins from Claude settings.

    Reads enabledPlugins from the settings dict.
    """
    return settings.get('enabledPlugins')


def _resolve_marketplace_path(marketplace: dict) -> Optional[Path]:
    """
    Resolve filesystem path for a directory-type marketplace.
    """
    source = marketplace.get('source', {})
    if source.get('source') != 'directory':
        return None
    raw = source.get('path')
    if not raw:
        return None
    path = Path(raw)
    return path if path.is_dir() else None


def _load_plugin_json_file(plugin_path: Path, relative_path: str) -> Optional[dict]:
    """Load and parse a JSON file inside a plugin directory.

    Returns None if the file is missing, unreadable, or has invalid JSON.
    """
    target = plugin_path / relative_path
    if not target.exists():
        return None
    try:
        return json.loads(target.read_text(encoding='utf-8'))
    except Exception as e:
        logger.debug('Failed to load plugin file', extra={'path': str(target)}, exc_info=e)
        return None


def resolve_plugins(settings: dict) -> tuple[dict, dict]:
    """Resolve enabled plugins to their MCP servers and metadata.

    Walks enabledPlugins from claude settings, resolves each plugin's 'marketplace' directory
    via the 'extraKnownMarketplaces' field, and reads:
      - <path>/.mcp.json for MCP servers (merged into a flat dict)
      - <path>/.claude-plugin/plugin.json for metadata (name, version, description)

    Args:
        settings: Parsed ~/.claude/settings.json dict.

    Returns:
        Tuple of (merged_mcp_servers, enriched_plugins):
          - merged_mcp_servers: {server_name: server_config, ...}
          - enriched_plugins: {plugin_key: {"enabled": True, "name": ..., ...}, ...}
    """
    enabled = settings.get('enabledPlugins') or {}
    marketplaces = settings.get('extraKnownMarketplaces') or {}
    merged_mcp: dict = {}
    enriched: dict = {}

    for plugin_key, is_enabled in enabled.items():
        if not is_enabled:
            continue

        entry: dict = {'enabled': True}
        enriched[plugin_key] = entry

        if '@' not in plugin_key:
            continue

        _plugin_name, marketplace_name = plugin_key.split('@', 1)
        marketplace = marketplaces.get(marketplace_name)
        if not marketplace:
            continue

        plugin_path = _resolve_marketplace_path(marketplace)
        if plugin_path is None:
            continue

        metadata = _load_plugin_json_file(plugin_path, '.claude-plugin/plugin.json') or {}
        for field in ('name', 'version', 'description'):
            if field in metadata:
                entry[field] = metadata[field]

        mcp_config = _load_plugin_json_file(plugin_path, '.mcp.json') or {}
        for server_name, server_cfg in (mcp_config.get('mcpServers') or {}).items():
            merged_mcp[server_name] = server_cfg

    return merged_mcp, enriched
