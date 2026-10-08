"""MCP server authorization status cache: session-start writes it, the pre-MCP-execution hook reads it.

An absent or corrupt cache means no status is known, so the guardrail fails open.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from marshmallow import EXCLUDE, Schema, fields, post_load

from cycode.cli.apps.ai_guardrails.scan.guardrail_config import DEFAULT_TTL_SECONDS
from cycode.cli.consts import CYCODE_CONFIGURATION_DIRECTORY
from cycode.cli.utils.path_utils import atomic_write_text, quarantine_corrupt_file
from cycode.cyclient.models import McpServerAuthorizationStatus, McpServerStatus, McpServerStatusSchema
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')

MCP_SERVER_STATUSES_FILE_NAME = 'ai-guardrails-mcp-servers.json'


# An alias shared by several servers (e.g. configured differently per device) gets the most restrictive status.
_RESTRICTIVENESS = {
    McpServerAuthorizationStatus.AUTHORIZED: 0,
    McpServerAuthorizationStatus.UNREVIEWED: 1,
    McpServerAuthorizationStatus.UNAUTHORIZED: 2,
}


def get_mcp_server_statuses_cache_path() -> Path:
    return Path.home() / CYCODE_CONFIGURATION_DIRECTORY / MCP_SERVER_STATUSES_FILE_NAME


def is_enforced(status: McpServerAuthorizationStatus | None) -> bool:
    """``status`` is None when the platform never saw the server."""
    return status == McpServerAuthorizationStatus.UNAUTHORIZED


@dataclass
class McpServerStatuses:
    servers: list[McpServerStatus]
    fetched_at: float
    tenant_id: str | None = None
    ttl_seconds: float = DEFAULT_TTL_SECONDS
    _by_alias: dict = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # The platform matches aliases case-insensitively, so the CLI does too.
        self._by_alias = {}
        for server in self.servers:
            if not server.alias:
                continue
            key = server.alias.lower()
            known = self._by_alias.get(key)
            if known is None or _RESTRICTIVENESS[server.status] > _RESTRICTIVENESS[known]:
                self._by_alias[key] = server.status

    def status_of(self, alias: str) -> McpServerAuthorizationStatus | None:
        return self._by_alias.get(alias.lower())


class McpServerStatusesSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    servers = fields.List(fields.Nested(McpServerStatusSchema), required=True)
    fetched_at = fields.Float(required=True)
    tenant_id = fields.String(allow_none=True, load_default=None)
    ttl_seconds = fields.Float(allow_none=True, load_default=None)

    @post_load
    def build_dto(self, data: dict[str, Any], **_) -> McpServerStatuses:
        data['ttl_seconds'] = data['ttl_seconds'] or DEFAULT_TTL_SECONDS
        return McpServerStatuses(**data)


def save_mcp_server_statuses(
    servers: list[McpServerStatus], tenant_id: str | None, ttl_seconds: float = DEFAULT_TTL_SECONDS
) -> None:
    path = get_mcp_server_statuses_cache_path()
    statuses = McpServerStatuses(servers=servers, fetched_at=time.time(), tenant_id=tenant_id, ttl_seconds=ttl_seconds)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(str(path), json.dumps(McpServerStatusesSchema().dump(statuses)))
    except Exception as e:
        logger.debug('Failed to save MCP server statuses cache', exc_info=e)


def load_mcp_server_statuses() -> McpServerStatuses | None:
    path = get_mcp_server_statuses_cache_path()
    if not path.exists():
        return None

    try:
        with open(path, encoding='UTF-8') as file:
            return McpServerStatusesSchema().load(json.load(file))
    except Exception as e:
        logger.warning('MCP server statuses cache is corrupt and will be moved aside', exc_info=e)
        quarantine_corrupt_file(str(path))
        return None
