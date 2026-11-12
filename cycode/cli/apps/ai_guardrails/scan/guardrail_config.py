"""Platform guardrail config cache.

session-start fetches the tenant's resolved guardrail config from the platform and writes it
here; scans only read. Per-agent modes and sensitive-path globs are platform-owned - local
policy files never carry them. An absent or corrupt cache means built-in defaults (Report
everywhere + the default globs, with the unauthorized MCP server guardrail Off), always synchronous.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from cycode.cli.apps.ai_guardrails.consts import GuardrailCellMode, PolicyMode
from cycode.cli.apps.ai_guardrails.scan.consts import DEFAULT_SENSITIVE_PATH_GLOBS
from cycode.cli.apps.ai_guardrails.scan.types import BlockReason
from cycode.cli.consts import CYCODE_CONFIGURATION_DIRECTORY
from cycode.cli.utils.path_utils import atomic_write_text, quarantine_corrupt_file
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')

GUARDRAILS_CONFIG_FILE_NAME = 'ai-guardrails-config.json'

DEFAULT_TTL_SECONDS = 900

# Guardrail keys are the CLI's block-reason vocabulary. Anything else in the payload (a future
# guardrail this CLI doesn't implement) is ignored - unknown config must never fail closed.
_KNOWN_GUARDRAIL_KEYS = frozenset(
    reason.value
    for reason in (
        BlockReason.SECRETS_IN_PROMPT,
        BlockReason.SECRETS_IN_FILE,
        BlockReason.SENSITIVE_PATH,
        BlockReason.SECRETS_IN_MCP_ARGS,
        BlockReason.UNAUTHORIZED_MCP_SERVER,
    )
)

# Off by default (not Report), so they never start enforcing on a tenant that hasn't configured them.
_DEFAULT_OFF_GUARDRAIL_KEYS = frozenset((BlockReason.UNAUTHORIZED_MCP_SERVER.value,))


def get_config_cache_path() -> Path:
    return Path.home() / CYCODE_CONFIGURATION_DIRECTORY / GUARDRAILS_CONFIG_FILE_NAME


def default_mode_for(guardrail_key: str) -> str:
    if guardrail_key in _DEFAULT_OFF_GUARDRAIL_KEYS:
        return GuardrailCellMode.OFF.value
    return GuardrailCellMode.REPORT.value


def _default_sensitive_globs() -> list:
    return list(DEFAULT_SENSITIVE_PATH_GLOBS)


@dataclass
class GuardrailConfig:
    payload: dict
    fetched_at: float
    tenant_id: str | None = None
    _guardrails: dict = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._guardrails = {
            guardrail.get('key'): guardrail
            for guardrail in self.payload.get('guardrails') or []
            if guardrail.get('key') in _KNOWN_GUARDRAIL_KEYS
        }

    @property
    def ttl_seconds(self) -> float:
        return self.payload.get('ttl_seconds') or DEFAULT_TTL_SECONDS

    def _agents(self, guardrail_key: str) -> dict:
        return (self._guardrails.get(guardrail_key) or {}).get('agents') or {}

    def mode_for(self, guardrail_key: str, ide_name: str | None) -> str:
        """The platform keys the cells by our --ide names, so the lookup is direct."""
        agents = self._agents(guardrail_key)
        return str(agents.get((ide_name or '').lower(), default_mode_for(guardrail_key))).lower()

    def is_off_for_every_agent(self, guardrail_key: str) -> bool:
        return all(str(mode).lower() == GuardrailCellMode.OFF for mode in self._agents(guardrail_key).values())

    def _modes_for_event(self, event_name: str, ide_name: str | None) -> list:
        return [
            self.mode_for(key, ide_name)
            for key, guardrail in self._guardrails.items()
            if str(guardrail.get('event_type', '')).lower() == str(event_name).lower()
        ]

    def is_event_off(self, event_name: str, ide_name: str | None) -> bool:
        """Every guardrail for this event is Off - skip the scan entirely."""
        modes = self._modes_for_event(event_name, ide_name)
        return bool(modes) and all(mode == GuardrailCellMode.OFF for mode in modes)

    def can_event_block(self, event_name: str, ide_name: str | None) -> bool:
        """At least one guardrail for this event is in Block mode - the scan must stay synchronous."""
        return GuardrailCellMode.BLOCK in self._modes_for_event(event_name, ide_name)

    def sensitive_globs(self) -> list:
        settings = (self._guardrails.get(BlockReason.SENSITIVE_PATH) or {}).get('settings') or {}
        globs = settings.get('globs')
        return globs if isinstance(globs, list) and globs else _default_sensitive_globs()

    def is_expired(self) -> bool:
        return time.time() - self.fetched_at > self.ttl_seconds

    def needs_refresh(self, tenant_id: str | None) -> bool:
        """Expired, or fetched for another tenant (the user switched tenants since)."""
        return self.is_expired() or self.tenant_id != tenant_id


def apply_platform_config(policy: dict, config: GuardrailConfig | None, ide_name: str | None) -> None:
    """Overlay the platform-owned enforcement config onto the local knobs-only policy.

    The platform is the only mode source: no cache (cold start) means the built-in defaults -
    Report everywhere (unauthorized MCP server Off) with the default globs - which equal an unconfigured
    tenant's platform config, so behaviour is uniform either way. Each matrix cell lands on its own
    per-feature action, so guardrails sharing an event (e.g. the two FileRead ones) keep independent modes.
    An all-Off event never reaches here at all: scan_command skips it.
    """

    def cell(guardrail_key: str) -> str:
        return config.mode_for(guardrail_key, ide_name) if config is not None else default_mode_for(guardrail_key)

    def action(guardrail_key: str) -> str:
        return PolicyMode.BLOCK.value if cell(guardrail_key) == GuardrailCellMode.BLOCK else PolicyMode.WARN.value

    policy.setdefault('prompt', {})['action'] = action(BlockReason.SECRETS_IN_PROMPT)

    file_read = policy.setdefault('file_read', {})
    file_read['scan_content'] = cell(BlockReason.SECRETS_IN_FILE) != GuardrailCellMode.OFF
    file_read['action'] = action(BlockReason.SECRETS_IN_FILE)
    file_read['deny_globs'] = (
        (config.sensitive_globs() if config is not None else _default_sensitive_globs())
        if cell(BlockReason.SENSITIVE_PATH) != GuardrailCellMode.OFF
        else []
    )
    file_read['path_action'] = action(BlockReason.SENSITIVE_PATH)

    mcp = policy.setdefault('mcp', {})
    mcp['scan_args'] = cell(BlockReason.SECRETS_IN_MCP_ARGS) != GuardrailCellMode.OFF
    mcp['action'] = action(BlockReason.SECRETS_IN_MCP_ARGS)
    mcp['check_server'] = cell(BlockReason.UNAUTHORIZED_MCP_SERVER) != GuardrailCellMode.OFF
    mcp['server_action'] = action(BlockReason.UNAUTHORIZED_MCP_SERVER)


def save_guardrail_config(payload: dict, tenant_id: str | None) -> None:
    """Persist a fetched resolved config; a failed write just leaves the previous cache in place."""
    path = get_config_cache_path()
    content = {'fetched_at': time.time(), 'tenant_id': tenant_id, 'payload': payload}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(str(path), json.dumps(content))
    except Exception as e:
        logger.debug('Failed to save guardrail config cache', exc_info=e)


def load_guardrail_config() -> GuardrailConfig | None:
    """The cached platform config, or None when it is absent or corrupt (quarantined)."""
    path = get_config_cache_path()
    if not path.exists():
        return None

    try:
        with open(path, encoding='UTF-8') as file:
            content = json.load(file)
        payload = content['payload']
        if not isinstance(payload, dict):
            raise TypeError('payload is not an object')
        return GuardrailConfig(
            payload=payload, fetched_at=float(content['fetched_at']), tenant_id=content.get('tenant_id')
        )
    except Exception as e:
        logger.warning('Guardrail config cache is corrupt and will be moved aside', exc_info=e)
        quarantine_corrupt_file(str(path))
        return None
