"""MCP server authorization status cache: session-start writes it, the pre-MCP-execution hook reads it.

An absent or corrupt cache means no status is known, so the guardrail fails open.
"""

import json
import time
from dataclasses import InitVar, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from cycode.cli.apps.ai_guardrails.scan.guardrail_config import DEFAULT_TTL_SECONDS
from cycode.cli.consts import CYCODE_CONFIGURATION_DIRECTORY
from cycode.cli.utils.path_utils import atomic_write_text, quarantine_corrupt_file
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')

MCP_SERVER_STATUSES_FILE_NAME = 'ai-guardrails-mcp-servers.json'


class McpServerAuthorizationStatus(str, Enum):
    AUTHORIZED = 'Authorized'
    UNREVIEWED = 'Unreviewed'
    UNAUTHORIZED = 'Unauthorized'


# An alias shared by several servers (e.g. configured differently per device) gets the most restrictive status.
_RESTRICTIVENESS = {
    McpServerAuthorizationStatus.AUTHORIZED: 0,
    McpServerAuthorizationStatus.UNREVIEWED: 1,
    McpServerAuthorizationStatus.UNAUTHORIZED: 2,
}


def get_mcp_server_statuses_cache_path() -> Path:
    return Path.home() / CYCODE_CONFIGURATION_DIRECTORY / MCP_SERVER_STATUSES_FILE_NAME


def parse_status(raw_status: object) -> McpServerAuthorizationStatus:
    """An unknown status reads as Unreviewed: no decision was made on the server."""
    lowered = str(raw_status or '').lower()
    for status in McpServerAuthorizationStatus:
        if status.value.lower() == lowered:
            return status
    return McpServerAuthorizationStatus.UNREVIEWED


def is_enforced(status: Optional[McpServerAuthorizationStatus]) -> bool:
    """``status`` is None when the platform never saw the server."""
    return status == McpServerAuthorizationStatus.UNAUTHORIZED


@dataclass
class McpServerStatuses:
    servers: InitVar[list]
    fetched_at: float
    tenant_id: Optional[str] = None
    ttl_seconds: float = DEFAULT_TTL_SECONDS
    _by_alias: dict = field(init=False, repr=False)

    def __post_init__(self, servers: list) -> None:
        # The platform matches aliases case-insensitively, so the CLI does too.
        self._by_alias = {}
        for server in servers:
            if not isinstance(server, dict) or not server.get('alias'):
                continue
            key = str(server['alias']).lower()
            status = parse_status(server.get('status'))
            known = self._by_alias.get(key)
            if known is None or _RESTRICTIVENESS[status] > _RESTRICTIVENESS[known]:
                self._by_alias[key] = status

    def status_of(self, alias: str) -> Optional[McpServerAuthorizationStatus]:
        return self._by_alias.get(alias.lower())

    def is_expired(self) -> bool:
        return time.time() - self.fetched_at > self.ttl_seconds

    def needs_refresh(self, tenant_id: Optional[str]) -> bool:
        return self.is_expired() or self.tenant_id != tenant_id


def save_mcp_server_statuses(servers: list, tenant_id: Optional[str], ttl_seconds: float = DEFAULT_TTL_SECONDS) -> None:
    path = get_mcp_server_statuses_cache_path()
    content = {
        'fetched_at': time.time(),
        'tenant_id': tenant_id,
        'ttl_seconds': ttl_seconds,
        'servers': servers,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(str(path), json.dumps(content))
    except Exception as e:
        logger.debug('Failed to save MCP server statuses cache', exc_info=e)


def load_mcp_server_statuses() -> Optional[McpServerStatuses]:
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
