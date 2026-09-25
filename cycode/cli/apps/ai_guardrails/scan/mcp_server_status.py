"""MCP server authorization status cache, for the unauthorized MCP server guardrail.

session-start fetches the authorization status of every MCP server the platform ingested from
this user's devices (Inventory -> AI Governance) and writes it here; the pre-MCP-execution hook
only reads it. An absent or corrupt cache means no status is known, so the guardrail fails open.
"""

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import NamedTuple, Optional

from cycode.cli.apps.ai_guardrails.consts import McpServerEnforceOn
from cycode.cli.apps.ai_guardrails.scan.guardrail_config import DEFAULT_TTL_SECONDS
from cycode.cli.consts import CYCODE_CONFIGURATION_DIRECTORY
from cycode.cli.utils.path_utils import atomic_write_text, quarantine_corrupt_file
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')

MCP_SERVER_STATUSES_FILE_NAME = 'ai-guardrails-mcp-servers.json'

# Claude Code namespaces a plugin's servers in tool names as `plugin_<plugin>_<server>`, while the
# platform stores the server under its config key - the name the session sweep reported.
_PLUGIN_ALIAS_PREFIX = 'plugin_'


class McpServerAuthorizationStatus(str, Enum):
    AUTHORIZED = 'Authorized'
    UNREVIEWED = 'Unreviewed'
    UNAUTHORIZED = 'Unauthorized'


# When one alias maps to several servers (e.g. the same name configured differently on two
# devices), the most restrictive status wins.
_RESTRICTIVENESS = {
    McpServerAuthorizationStatus.AUTHORIZED: 0,
    McpServerAuthorizationStatus.UNREVIEWED: 1,
    McpServerAuthorizationStatus.UNAUTHORIZED: 2,
}


def get_mcp_server_statuses_cache_path() -> Path:
    return Path.home() / CYCODE_CONFIGURATION_DIRECTORY / MCP_SERVER_STATUSES_FILE_NAME


def parse_status(raw_status: object) -> McpServerAuthorizationStatus:
    """Case-insensitive; an unknown status reads as Unreviewed (no decision was made on the server)."""
    lowered = str(raw_status or '').lower()
    for status in McpServerAuthorizationStatus:
        if status.value.lower() == lowered:
            return status
    return McpServerAuthorizationStatus.UNREVIEWED


def _normalize_alias(alias: str) -> str:
    """The form an IDE may turn a config name into inside a tool name (Claude Code keeps [A-Za-z0-9_-])."""
    return re.sub(r'[^a-z0-9_-]', '_', alias.lower())


def is_enforced(status: Optional[McpServerAuthorizationStatus], enforce_on: str) -> bool:
    """Whether a server with this status (None: the platform never saw it) is enforced under `enforce_on`."""
    if status == McpServerAuthorizationStatus.UNAUTHORIZED:
        return True
    return enforce_on == McpServerEnforceOn.NOT_AUTHORIZED and status != McpServerAuthorizationStatus.AUTHORIZED


class McpServerMatch(NamedTuple):
    alias: str  # as the platform stores it
    status: McpServerAuthorizationStatus


@dataclass
class McpServerStatuses:
    servers: list
    fetched_at: float
    tenant_id: Optional[str] = None
    ttl_seconds: float = DEFAULT_TTL_SECONDS
    _by_alias: dict = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Lowered alias -> (stored alias, most restrictive status). The platform matches aliases
        # case-insensitively, so the CLI does too.
        self._by_alias = {}
        for server in self.servers:
            if not isinstance(server, dict) or not server.get('alias'):
                continue
            alias = str(server['alias'])
            status = parse_status(server.get('status'))
            known = self._by_alias.get(alias.lower())
            if known is None or _RESTRICTIVENESS[status] > _RESTRICTIVENESS[known.status]:
                self._by_alias[alias.lower()] = McpServerMatch(alias, status)

    def match(self, alias: str) -> Optional[McpServerMatch]:
        """The platform's entry for the alias a hook reported, or None when the platform has none."""
        exact = self._by_alias.get(alias.lower())
        if exact is not None:
            return exact

        wanted = _normalize_alias(alias)
        normalized = [known for key, known in self._by_alias.items() if _normalize_alias(key) == wanted]
        if not normalized and wanted.startswith(_PLUGIN_ALIAS_PREFIX):
            # The plugin name may itself contain '_', so the server is the longest known suffix.
            suffixes = [
                (len(_normalize_alias(key)), known)
                for key, known in self._by_alias.items()
                if wanted.endswith(f'_{_normalize_alias(key)}')
            ]
            longest = max((length for length, _ in suffixes), default=None)
            normalized = [known for length, known in suffixes if length == longest]

        return max(normalized, key=lambda known: _RESTRICTIVENESS[known.status], default=None)

    def is_expired(self) -> bool:
        return time.time() - self.fetched_at > self.ttl_seconds

    def needs_refresh(self, tenant_id: Optional[str]) -> bool:
        """Expired, or fetched for another tenant (the user switched tenants since)."""
        return self.is_expired() or self.tenant_id != tenant_id


def save_mcp_server_statuses(servers: list, tenant_id: Optional[str], ttl_seconds: float = DEFAULT_TTL_SECONDS) -> None:
    """Persist fetched statuses; a failed write just leaves the previous cache in place."""
    path = get_mcp_server_statuses_cache_path()
    content = {'fetched_at': time.time(), 'tenant_id': tenant_id, 'ttl_seconds': ttl_seconds, 'servers': servers}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(str(path), json.dumps(content))
    except Exception as e:
        logger.debug('Failed to save MCP server statuses cache', exc_info=e)


def load_mcp_server_statuses() -> Optional[McpServerStatuses]:
    """The cached statuses, or None when the cache is absent or corrupt (quarantined)."""
    path = get_mcp_server_statuses_cache_path()
    if not path.exists():
        return None

    try:
        with open(path, encoding='UTF-8') as file:
            content = json.load(file)
        servers = content['servers']
        if not isinstance(servers, list):
            raise ValueError('servers is not a list')
        return McpServerStatuses(
            servers=servers,
            fetched_at=float(content['fetched_at']),
            tenant_id=content.get('tenant_id'),
            ttl_seconds=float(content.get('ttl_seconds') or DEFAULT_TTL_SECONDS),
        )
    except Exception as e:
        logger.warning('MCP server statuses cache is corrupt and will be moved aside', exc_info=e)
        quarantine_corrupt_file(str(path))
        return None
