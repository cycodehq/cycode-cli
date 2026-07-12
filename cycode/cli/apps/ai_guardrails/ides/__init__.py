"""Registry of supported AI guardrails IDE integrations.

Adding a new IDE: create `ides/<name>.py` with a subclass of `IDE`, import it
here, and include an instance in the `IDES` tuple. Nothing else in the package
needs to change.
"""

import typer

from cycode.cli.apps.ai_guardrails.ides.base import IDE
from cycode.cli.apps.ai_guardrails.ides.claude_code import ClaudeCode
from cycode.cli.apps.ai_guardrails.ides.codex import Codex
from cycode.cli.apps.ai_guardrails.ides.cursor import Cursor

# Single source of truth: name → singleton instance.
# `--ide` choices and install/uninstall/status iteration both derive from this.
IDES: dict[str, IDE] = {ide.name: ide for ide in (Cursor(), ClaudeCode(), Codex())}

# Default IDE used when `--ide` is omitted. Kept here so the value is colocated
# with the registry; no module outside `ides/` needs to know which IDE wins.
DEFAULT_IDE_NAME = 'cursor'


def get_ide(name: str) -> IDE:
    """Look up the IDE integration registered under ``name``.

    Raises ``typer.BadParameter`` when the name is unknown — surfaces as a
    user-friendly CLI error rather than a KeyError stack trace.
    """
    ide = IDES.get(name.lower())
    if ide is None:
        valid = ', '.join(IDES.keys())
        raise typer.BadParameter(f'Unknown IDE "{name}". Supported: {valid}.')
    return ide


def collect_all_session_contexts() -> tuple[dict[str, dict], dict]:
    """Sweep every registered IDE's session context, regardless of which IDE triggered the hook.

    Returns ``(config_files_by_ide, plugins)``: the global MCP config file of each IDE that has
    one (keyed by IDE name), and the enabled plugins merged across IDEs (first registered IDE
    wins on a duplicate plugin key - plugins are IDE-agnostic marketplace artifacts).
    """
    config_files_by_ide: dict[str, dict] = {}
    plugins: dict = {}
    for ide in IDES.values():
        global_config_file, enabled_plugins = ide.get_session_context()
        if global_config_file:
            config_files_by_ide[ide.name] = global_config_file
        for plugin_key, plugin in (enabled_plugins or {}).items():
            plugins.setdefault(plugin_key, plugin)

    return config_files_by_ide, plugins


def resolve_ides(name: str) -> list[IDE]:
    """Resolve an ``--ide`` argument to one or all IDE instances.

    ``"all"`` returns every registered IDE; anything else returns a single
    matching IDE (raising ``typer.BadParameter`` for unknown names).
    """
    if name.lower() == 'all':
        return list(IDES.values())
    return [get_ide(name)]
