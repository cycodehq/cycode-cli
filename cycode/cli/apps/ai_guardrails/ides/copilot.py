"""GitHub Copilot integration for AI guardrails.

Hooks are installed in Copilot's native format to ``~/.copilot/hooks/cycode.json``
(user scope) or ``<repo>/.github/hooks/cycode.json`` (repo scope). One file, but
two runtimes are known to execute it: VS Code's own chat runtime, and the Copilot
agent runtime (Copilot CLI, and VS Code agent sessions). The repo-scope location
is also read by the Copilot cloud coding agent, whose dialect is untested here.

Both deliver Claude-style payloads (``hook_event_name``, ``tool_name``,
``tool_input``) when the event keys are registered in PascalCase; the agent runtime
answers camelCase keys with its own dialect (``sessionId``, no event name) instead.
Copilot payloads are told apart from Claude Code's by the one field Claude Code
never sends, a top-level ``timestamp``; ``transcript_path`` cannot discriminate,
since VS Code sends one of its own whenever a folder is open.

The tool vocabulary still differs by runtime — VS Code reads files with
``read_file``/``filePath`` and names MCP tools ``mcp_<server>_<tool>``, the agent
runtime uses ``Read``/``path`` and ``<server>-<tool>`` — so both are accepted.
Copilot hooks have no matchers, so ``PreToolUse`` fires for every tool; tools we
don't scan pass through as raw event names, which match no handler and allow
immediately.
"""

import json
import os
import platform
import re
from collections.abc import Iterable
from pathlib import Path
from typing import ClassVar, Optional, Union
from urllib.parse import urlparse
from urllib.request import url2pathname

from cycode.cli.apps.ai_guardrails.consts import CYCODE_SCAN_PROMPT_COMMAND, CYCODE_SESSION_START_COMMAND
from cycode.cli.apps.ai_guardrails.ides._plugin_utils import (
    build_global_config_file,
    load_plugin_json,
    walk_enabled_plugins,
)
from cycode.cli.apps.ai_guardrails.ides.base import IDE, DecisionAction, HookDecision
from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType
from cycode.logger import get_logger

logger = get_logger('AI Guardrails Copilot')

# Payload dialect (Claude-style PascalCase event names).
_COPILOT_SCAN_EVENT_NAMES = frozenset({'UserPromptSubmit', 'PreToolUse'})

# Two tool vocabularies reach us through one hooks file: VS Code's own runtime
# names file reads `read_file` with a `filePath` argument, while the Copilot agent
# runtime (Copilot CLI, and VS Code agent sessions) names them `Read` with `path`.
# The names are disjoint, so both are accepted rather than switched between.
_READ_FILE_TOOLS = frozenset({'read_file', 'Read'})
_READ_PATH_KEYS = ('path', 'filePath')

# VS Code names MCP tools `mcp_<server>_<tool>` (single underscores); the agent
# runtime uses `<server>-<tool>` with no prefix (its SDK documents that wire form),
# leaving a hyphen as the only marker of an MCP call there. Every built-in agent
# tool observed is lower snake_case (`view`, `glob`, `str_replace`, `ask_user`) or
# PascalCase (`Read`), so this holds for them — but SDK- or custom-agent-registered
# tools may be named freely. A hyphenated custom tool would be scanned as an MCP
# call with no resolvable server: an extra scan, never a missed one, which is the
# safe direction to err for a guardrail.
_MCP_TOOL_PREFIX = 'mcp_'
_MCP_AGENT_SEPARATOR = '-'

# Hooks-file event keys. Their case selects the agent runtime's payload dialect.
_HOOK_EVENTS = ['UserPromptSubmit', 'PreToolUse']

_COPILOT_HOME_ENV_VAR = 'COPILOT_HOME'
_HOOKS_FILE_NAME = 'cycode.json'
_REPO_HOOKS_SUBDIR = Path('.github') / 'hooks'
_HOOK_TIMEOUT_SEC = 20
_MCP_CONFIG_FILENAME = 'mcp.json'
_AGENT_MCP_CONFIG_FILENAME = 'mcp-config.json'

# Plugin sources. CLI installs register in ~/.copilot/config.json and auto-surface
# in VS Code; VS Code UI installs register in ~/.vscode/agent-plugins/installed.json;
# local-directory plugins are declared via the chat.pluginLocations setting.
_VSCODE_PLUGINS_REGISTRY_NAME = 'installed.json'
_PLUGIN_LOCATIONS_SETTING = 'chat.pluginLocations'
_LOCAL_PLUGINS_MARKETPLACE = 'local'

# Manifest locations in VS Code's documented detection order. Plugins may ship
# several manifest dialects at once — first hit wins, matching VS Code's probing.
_PLUGIN_MANIFEST_LOCATIONS = (
    Path('.plugin') / 'plugin.json',
    Path('plugin.json'),
    Path('.github') / 'plugin' / 'plugin.json',
    Path('.claude-plugin') / 'plugin.json',
)

# One command for both events: every runtime self-describes via hook_event_name once
# the events are registered in PascalCase, so --event is no longer passed.
_SCAN_COMMAND = f'{CYCODE_SCAN_PROMPT_COMMAND} --ide copilot'
_SESSION_START_COMMAND = f'{CYCODE_SESSION_START_COMMAND} --ide copilot'


def _copilot_home() -> Path:
    """Resolve Copilot's user-scope home directory (honors ``$COPILOT_HOME``)."""
    override = os.environ.get(_COPILOT_HOME_ENV_VAR)
    if override:
        return Path(override)
    return Path.home() / '.copilot'


def _vscode_agent_plugins_dir() -> Path:
    # Resolved at call time (not a module-level Path constant): on py<=3.10 a Path
    # instance binds its filesystem accessor at creation, which breaks fake-fs tests
    # and ignores home changes.
    return Path.home() / '.vscode' / 'agent-plugins'


def _vscode_user_dir() -> Path:
    """Per-platform VS Code user settings directory."""
    if platform.system() == 'Darwin':
        return Path.home() / 'Library' / 'Application Support' / 'Code' / 'User'
    if platform.system() == 'Windows':
        return Path.home() / 'AppData' / 'Roaming' / 'Code' / 'User'
    return Path.home() / '.config' / 'Code' / 'User'


def _vscode_mcp_config_path() -> Path:
    return _vscode_user_dir() / _MCP_CONFIG_FILENAME


def _load_vscode_mcp_config(config_path: Optional[Path] = None) -> Optional[dict]:
    """Load and parse VS Code's user-level ``mcp.json``. Returns None if missing/invalid."""
    path = config_path or _vscode_mcp_config_path()
    if not path.exists():
        logger.debug('VS Code MCP config file not found, %s', {'path': str(path)})
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception as e:
        logger.debug('Failed to load VS Code MCP config file', exc_info=e)
        return None


def _load_jsonc(path: Path) -> Optional[dict]:
    """Parse a JSON file tolerating //-comment lines (Copilot's config.json ships
    with a comment header; VS Code's settings.json is JSONC).

    Best-effort: JSONC constructs beyond full-line comments (trailing commas,
    inline comments) read as a missing file.
    """
    if not path.exists():
        logger.debug('Config file not found, %s', {'path': str(path)})
        return None
    try:
        text = path.read_text(encoding='utf-8')
        stripped = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('//'))
        return json.loads(stripped)
    except Exception as e:
        logger.debug('Failed to load config file, %s', {'path': str(path)}, exc_info=e)
        return None


# --- plugins inventory ----------------------------------------------------------


def _read_copilot_plugin(plugin_dir: Path) -> tuple[dict, dict]:
    """Read one Copilot plugin's manifest + MCP servers.

    The manifest's ``mcpServers`` field, when present, is a path string to the MCP
    file; otherwise the root ``.mcp.json`` convention applies (same as Claude
    plugins). Both forms exist in marketplace plugins.
    """
    manifest: dict = {}
    for location in _PLUGIN_MANIFEST_LOCATIONS:
        manifest = load_plugin_json(plugin_dir / location) or {}
        if manifest:
            break

    entry: dict = {}
    for field in ('name', 'version', 'description'):
        if field in manifest:
            entry[field] = manifest[field]

    mcp_ref = manifest.get('mcpServers')
    mcp_config_path = plugin_dir / mcp_ref if isinstance(mcp_ref, str) else plugin_dir / '.mcp.json'
    mcp_doc = load_plugin_json(mcp_config_path) or {}
    servers = mcp_doc.get('mcpServers')
    if not isinstance(servers, dict):
        servers = {}
    if servers:
        entry['mcp_server_names'] = list(servers.keys())
        entry['mcp_config_file_path'] = str(mcp_config_path)
        entry['mcp_config_file'] = json.dumps({'mcpServers': servers})
    return entry, servers


def _walk_registry_plugins(entries: dict[str, dict], dirs: dict[str, Path], is_enabled: bool = True) -> dict:
    """Walk plugins whose directories are known up front (registry-provided)."""
    return walk_enabled_plugins(
        plugin_entries=entries,
        is_enabled=lambda p: p.get('enabled', True) if is_enabled else True,
        locate_dir=lambda name, marketplace: dirs.get(f'{name}@{marketplace}'),
        read_plugin=_read_copilot_plugin,
    )


def _cli_registry_plugins() -> dict:
    """Plugins installed via Copilot CLI: ``~/.copilot/config.json`` → ``installedPlugins``."""
    config = _load_jsonc(_copilot_home() / 'config.json') or {}
    entries: dict[str, dict] = {}
    dirs: dict[str, Path] = {}
    for plugin in config.get('installedPlugins') or []:
        if not isinstance(plugin, dict) or not plugin.get('name'):
            continue
        key = f'{plugin["name"]}@{plugin.get("marketplace", "")}'
        entries[key] = plugin
        if plugin.get('cache_path'):
            dirs[key] = Path(plugin['cache_path'])
    return _walk_registry_plugins(entries, dirs)


def _vscode_registry_plugins() -> dict:
    """Plugins installed via the VS Code UI (@agentPlugins): ``~/.vscode/agent-plugins/installed.json``.

    Registry-driven only — the directory also holds marketplace clones that are
    not installed. ``pluginUri`` is the authoritative location (the registry's
    ``marketplace`` label is unreliable); presence in the registry means enabled.
    """
    registry = load_plugin_json(_vscode_agent_plugins_dir() / _VSCODE_PLUGINS_REGISTRY_NAME) or {}
    entries: dict[str, dict] = {}
    dirs: dict[str, Path] = {}
    for plugin in registry.get('installed') or []:
        if not isinstance(plugin, dict) or not plugin.get('name'):
            continue
        key = f'{plugin["name"]}@{plugin.get("marketplace", "")}'
        entries[key] = plugin
        uri = plugin.get('pluginUri', '')
        if uri.startswith('file://'):
            # url2pathname unquotes and handles Windows drive-letter URIs (file:///C:/...).
            dirs[key] = Path(url2pathname(urlparse(uri).path))
    return _walk_registry_plugins(entries, dirs, is_enabled=False)


def _local_dir_plugins() -> dict:
    """Local-directory plugins declared via the ``chat.pluginLocations`` setting."""
    settings = _load_jsonc(_vscode_user_dir() / 'settings.json') or {}
    locations = settings.get(_PLUGIN_LOCATIONS_SETTING)
    if not isinstance(locations, dict):
        return {}
    entries: dict[str, bool] = {}
    dirs: dict[str, Path] = {}
    for raw_path, enabled in locations.items():
        path = Path(raw_path).expanduser()
        key = f'{path.name}@{_LOCAL_PLUGINS_MARKETPLACE}'
        entries[key] = bool(enabled)
        dirs[key] = path
    return walk_enabled_plugins(
        plugin_entries=entries,
        is_enabled=bool,
        locate_dir=lambda name, marketplace: dirs.get(f'{name}@{marketplace}'),
        read_plugin=_read_copilot_plugin,
    )


def _collect_installed_plugins() -> dict:
    """Merge the three plugin sources (first source wins on a duplicate key)."""
    plugins: dict = {}
    for source in (_cli_registry_plugins, _vscode_registry_plugins, _local_dir_plugins):
        for key, entry in source().items():
            plugins.setdefault(key, entry)
    return plugins


# --- MCP tool-name splitting ------------------------------------------------------


def _known_mcp_server_names() -> list[str]:
    """Config-declared MCP server names, across both runtimes' config files.

    VS Code declares them in its user-level ``mcp.json`` under ``servers``; the
    agent runtime uses ``~/.copilot/mcp-config.json`` under ``mcpServers``. Both are
    read because one hooks file serves both, and plugin configs contribute to either.

    Best-effort inventory: servers contributed by extensions, ``chat.mcp.discovery``
    imports, dev containers, or non-default profiles are not discoverable from disk.
    """
    config = _load_vscode_mcp_config()
    servers = (config or {}).get('servers')
    names = list(servers.keys()) if isinstance(servers, dict) else []

    agent_config = _load_jsonc(_copilot_home() / _AGENT_MCP_CONFIG_FILENAME) or {}
    agent_servers = agent_config.get('mcpServers')
    if isinstance(agent_servers, dict):
        names.extend(agent_servers.keys())

    for plugin in _collect_installed_plugins().values():
        names.extend(plugin.get('mcp_server_names') or [])
    return names


def _server_name_variants(server_name: str) -> set[str]:
    """Normalized forms a config name may take inside a VS Code tool-name prefix.

    The prefix derives from the server's self-reported handshake name, which often
    resembles the config name modulo case and separators (a server configured as
    ``dummy-tracker`` self-reporting ``DummyTracker`` yields prefix ``dummytracker``).
    """
    lowered = server_name.lower()
    underscored = re.sub(r'[^a-z0-9]+', '_', lowered).strip('_')
    collapsed = re.sub(r'[^a-z0-9]', '', lowered)
    return {v for v in (server_name, underscored, collapsed) if v}


def _read_file_path(tool_name: str, tool_input: object) -> Optional[str]:
    """Path of a file-read tool call, or None when this isn't one.

    The agent runtime reuses its read tool for directory listings, with a payload
    identical to a file read, so the path has to be stat-ed to tell them apart —
    VS Code has no such ambiguity (`read_file` vs `list_dir`). A path that isn't an
    existing file (a directory, or already deleted) has nothing to scan.
    """
    if tool_name not in _READ_FILE_TOOLS or not isinstance(tool_input, dict):
        return None

    raw_path = next((tool_input[key] for key in _READ_PATH_KEYS if tool_input.get(key)), None)
    if not isinstance(raw_path, str):
        return None

    try:
        if not Path(raw_path).is_file():
            return None
    except OSError:
        return None
    return raw_path


def is_mcp_tool_name(tool_name: str) -> bool:
    """Whether a tool name is an MCP call in either runtime's naming scheme."""
    return tool_name.startswith(_MCP_TOOL_PREFIX) or _MCP_AGENT_SEPARATOR in tool_name


def split_mcp_tool_name(tool_name: str, server_names: Iterable[str]) -> tuple[Optional[str], Optional[str]]:
    """Split an MCP tool name into ``(server, tool)``.

    Handles both naming schemes: VS Code's ``mcp_<server>_<tool>`` and the agent
    runtime's prefix-less ``<server>-<tool>``. In the VS Code form the ``<server>``
    part is a sanitized (and possibly truncated) form of the server's SELF-REPORTED
    handshake name rather than the config key, so matching against known config
    names (and their normalized variants) is best-effort. Server names may
    themselves contain the separator, hence the longest-match. When nothing
    matches, return the unsplit remainder as the tool rather than fabricating a
    server from a guessed split.
    """
    if tool_name.startswith(_MCP_TOOL_PREFIX):
        rest, separator = tool_name[len(_MCP_TOOL_PREFIX) :], '_'
    else:
        rest, separator = tool_name, _MCP_AGENT_SEPARATOR

    best_server = None
    best_variant_len = -1
    for server in server_names:
        for variant in _server_name_variants(server):
            if (rest == variant or rest.startswith(f'{variant}{separator}')) and len(variant) > best_variant_len:
                best_server = server
                best_variant_len = len(variant)
    if best_server is not None:
        return best_server, rest[best_variant_len + 1 :] or None

    return None, rest or None


class Copilot(IDE):
    name: ClassVar[str] = 'copilot'
    display_name: ClassVar[str] = 'GitHub Copilot'
    hook_events: ClassVar[list[str]] = list(_HOOK_EVENTS)

    def settings_path(self, scope: str, repo_path: Optional[Path] = None) -> Path:
        # Dedicated Cycode-owned file (Copilot reads every *.json in the hooks
        # dir), unlike the shared settings files of other IDEs.
        if scope == 'repo' and repo_path:
            return repo_path / _REPO_HOOKS_SUBDIR / _HOOKS_FILE_NAME
        return _copilot_home() / 'hooks' / _HOOKS_FILE_NAME

    def render_hooks_config(self, async_mode: bool = False) -> dict:
        def entry(command: str) -> dict:
            if async_mode:
                # Copilot has no async hook flag; background via shell on unix. Both
                # redirects are load-bearing. `<&0` keeps the payload flowing: a bare
                # `cmd &` gets its stdin reattached to /dev/null by the shell (job
                # control is off in hooks), so the scan reads nothing and allows. The
                # stdout redirect is what actually makes it async: the backgrounded
                # child inherits the hook's stdout and the runner waits on that pipe
                # for EOF, so without it the scan blocks the response it was meant to
                # run behind. Windows PowerShell has no trailing-&, so it stays sync.
                return {
                    'type': 'command',
                    'bash': f'{command} <&0 >/dev/null 2>&1 &',
                    'powershell': command,
                    'timeoutSec': _HOOK_TIMEOUT_SEC,
                }
            # Single cross-platform `command` field, copied to both shells by Copilot.
            return {'type': 'command', 'command': command, 'timeoutSec': _HOOK_TIMEOUT_SEC}

        return {
            'version': 1,
            'hooks': {
                'SessionStart': [{'type': 'command', 'command': _SESSION_START_COMMAND}],
                'UserPromptSubmit': [entry(_SCAN_COMMAND)],
                'PreToolUse': [entry(_SCAN_COMMAND)],
            },
        }

    def matches_payload(self, raw_payload: dict) -> bool:
        # Structural discrimination, no magic strings: Copilot events carry a top-level
        # timestamp, Claude Code events never do.
        return raw_payload.get('hook_event_name', '') in _COPILOT_SCAN_EVENT_NAMES and 'timestamp' in raw_payload

    def parse_hook_payload(self, raw_payload: dict) -> AIHookPayload:
        hook_event_name = raw_payload.get('hook_event_name', '')
        tool_name = raw_payload.get('tool_name', '')
        tool_input = raw_payload.get('tool_input')

        read_path = _read_file_path(tool_name, tool_input)

        if hook_event_name == 'UserPromptSubmit':
            canonical_event: Union[AiHookEventType, str] = AiHookEventType.PROMPT
        elif hook_event_name == 'PreToolUse' and read_path is not None:
            canonical_event = AiHookEventType.FILE_READ
        elif hook_event_name == 'PreToolUse' and is_mcp_tool_name(tool_name):
            canonical_event = AiHookEventType.MCP_EXECUTION
        else:
            # No matchers in Copilot hooks: PreToolUse fires for every tool. Pass
            # the raw tool name through — it matches no handler, so scan_command
            # answers with a neutral allow before any policy/network work.
            canonical_event = tool_name or hook_event_name

        file_path = read_path if canonical_event == AiHookEventType.FILE_READ else None

        mcp_server_name = None
        mcp_tool_name = None
        mcp_arguments = None
        if canonical_event == AiHookEventType.MCP_EXECUTION:
            mcp_server_name, mcp_tool_name = split_mcp_tool_name(tool_name, _known_mcp_server_names())
            mcp_arguments = tool_input if isinstance(tool_input, dict) else None

        return AIHookPayload(
            event_name=canonical_event,
            conversation_id=raw_payload.get('session_id'),
            ide_provider=self.name,
            prompt=raw_payload.get('prompt', ''),
            file_path=file_path,
            mcp_server_name=mcp_server_name,
            mcp_tool_name=mcp_tool_name,
            mcp_arguments=mcp_arguments,
        )

    def build_hook_response(self, decision: HookDecision) -> dict:
        if decision.action == DecisionAction.ALLOW:
            # Neutral allow: {} means "no objection", leaving VS Code's own
            # permission flow intact. An explicit permissionDecision "allow" would
            # pre-approve the tool past the user's confirmation prompts — and with
            # no matchers that would cover every tool, not just scanned ones.
            return {}

        if decision.event_type == AiHookEventType.PROMPT:
            reason = decision.user_message or ''
            # decision/reason is what VS Code acts on; continue/stopReason/systemMessage
            # are the generic top-level fields — the combo is what was verified live.
            return {
                'decision': 'block',
                'reason': reason,
                'continue': False,
                'stopReason': reason,
                'systemMessage': reason,
            }

        return {
            'hookSpecificOutput': {
                'hookEventName': 'PreToolUse',
                'permissionDecision': decision.action.value,  # 'deny' or 'ask'
                'permissionDecisionReason': decision.user_message or '',
            }
        }

    def build_session_payload(self, raw_payload: dict) -> AIHookPayload:
        return AIHookPayload(
            conversation_id=raw_payload.get('session_id'),
            model=raw_payload.get('model'),
            ide_provider=self.name,
            source=raw_payload.get('source'),
        )

    def get_session_context(self) -> tuple[Optional[dict], dict]:
        # VS Code's mcp.json uses `servers` as its top-level key; normalized to the
        # canonical mcpServers shape by build_global_config_file.
        config = _load_vscode_mcp_config()
        global_config_file = (
            build_global_config_file(_vscode_mcp_config_path(), config.get('servers')) if config else None
        )
        return global_config_file, _collect_installed_plugins()
