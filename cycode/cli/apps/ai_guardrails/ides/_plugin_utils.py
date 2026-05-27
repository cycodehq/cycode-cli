"""Shared plugin-resolution helpers for IDE integrations.

Both Claude Code and Codex use the same ``<plugin>@<marketplace>`` key convention
and emit the same telemetry shape — only the marketplace layout and manifest
location differ. ``walk_enabled_plugins`` is the IDE-agnostic loop; each IDE
supplies the two callables that vary (``locate_dir`` + ``read_plugin``).
"""

import json
from pathlib import Path
from typing import Any, Callable, Optional

from cycode.logger import get_logger

logger = get_logger('AI Guardrails Plugins')


def load_plugin_json(path: Path) -> Optional[dict]:
    """Load a JSON file inside a plugin directory; None if missing or invalid."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception as e:
        logger.debug('Failed to load plugin file, %s', {'path': str(path)}, exc_info=e)
        return None


def walk_enabled_plugins(
    plugin_entries: dict[str, Any],
    is_enabled: Callable[[Any], bool],
    locate_dir: Callable[[str, str], Optional[Path]],
    read_plugin: Callable[[Path], tuple[dict, dict]],
) -> tuple[dict, dict]:
    """Iterate enabled plugins; merge their MCP servers and metadata.

    Args:
        plugin_entries: ``{<plugin>@<marketplace>: settings}`` map from the IDE config.
        is_enabled: returns True if ``settings`` indicates the plugin is on
            (e.g. ``bool(settings)`` for Claude, ``settings.get('enabled')`` for Codex).
        locate_dir: given ``(plugin_name, marketplace)``, returns the plugin's
            filesystem path or None if it can't be resolved.
        read_plugin: given the plugin path, returns ``(entry_fields, servers)``:
            ``entry_fields`` are extra metadata to attach to the inventory entry
            (name/version/description/...), ``servers`` are MCP servers contributed.

    Returns ``(merged_mcp_servers, enriched_plugins)``. Plugin keys without
    ``@`` (or that fail to resolve to a directory) still appear in the
    inventory with just ``{'enabled': True}`` so we don't silently drop them.
    """
    merged_mcp: dict = {}
    enriched: dict = {}

    for plugin_key, settings in plugin_entries.items():
        if not is_enabled(settings):
            continue

        entry: dict = {'enabled': True}
        enriched[plugin_key] = entry

        if '@' not in plugin_key:
            continue
        plugin_name, marketplace = plugin_key.split('@', 1)

        plugin_dir = locate_dir(plugin_name, marketplace)
        if plugin_dir is None:
            continue

        plugin_fields, servers = read_plugin(plugin_dir)
        entry.update(plugin_fields)
        merged_mcp.update(servers)

    return merged_mcp, enriched
