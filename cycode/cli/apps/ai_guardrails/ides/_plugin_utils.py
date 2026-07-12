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


def resolve_cached_plugin_dir(cache_root: Path, marketplace: str, plugin_name: str) -> Optional[Path]:
    """Find ``<cache_root>/<marketplace>/<plugin>/<version-or-hash>/``.

    Both Claude Code and Codex cache installed plugin content in this layout (the trailing
    segment is a version for Claude, a content hash for Codex). If multiple are cached, pick
    the most recently modified.
    """
    base = cache_root / marketplace / plugin_name
    if not base.is_dir():
        return None
    candidates = [d for d in base.iterdir() if d.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda d: d.stat().st_mtime)


def load_plugin_json(path: Path) -> Optional[dict]:
    """Load a JSON file inside a plugin directory; None if missing or invalid."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception as e:
        logger.debug('Failed to load plugin file, %s', {'path': str(path)}, exc_info=e)
        return None


def build_global_config_file(path: Path, mcp_servers: Optional[dict]) -> Optional[dict]:
    """Wrap a global (non-plugin) MCP config into the session-context file shape.

    Returns ``{"path": <full path>, "content": <{"mcpServers": ...} JSON>}`` when
    there are servers, else ``None``. ``content`` is normalized to the canonical
    ``{"mcpServers": {...}}`` shape, dropping everything else in the source file.
    """
    servers = mcp_servers or {}
    if not servers:
        return None
    return {'path': str(path), 'content': json.dumps({'mcpServers': servers})}


def walk_enabled_plugins(
    plugin_entries: dict[str, Any],
    is_enabled: Callable[[Any], bool],
    locate_dir: Callable[[str, str], Optional[Path]],
    read_plugin: Callable[[Path], tuple[dict, dict]],
) -> dict:
    """Iterate enabled plugins and build their inventory metadata.

    Args:
        plugin_entries: ``{<plugin>@<marketplace>: settings}`` map from the IDE config.
        is_enabled: returns True if ``settings`` indicates the plugin is on
            (e.g. ``bool(settings)`` for Claude, ``settings.get('enabled')`` for Codex).
        locate_dir: given ``(plugin_name, marketplace)``, returns the plugin's
            filesystem path or None if it can't be resolved.
        read_plugin: given the plugin path, returns ``(entry_fields, servers)``:
            ``entry_fields`` are extra metadata to attach to the inventory entry
            (name/version/description/...); ``servers`` are the plugin's MCP
            servers, which ``read_plugin`` uses to derive that metadata.

    Returns ``enriched_plugins``. Plugin keys without ``@`` (or that fail to
    resolve to a directory) still appear in the inventory with just
    ``{'enabled': True}`` so we don't silently drop them.
    """
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

        plugin_fields, _ = read_plugin(plugin_dir)
        entry.update(plugin_fields)

    return enriched
