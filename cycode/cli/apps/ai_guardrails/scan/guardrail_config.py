"""Platform guardrail config cache.

session-start fetches the tenant's resolved guardrail config from the platform and writes it
here; scans only read. Per-agent modes and sensitive-path globs are platform-owned - local
policy files never carry them. An absent or corrupt cache means built-in defaults (Report
everywhere + the default globs), always synchronous.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from cycode.cli.apps.ai_guardrails.consts import GuardrailsMode, PolicyMode
from cycode.cli.apps.ai_guardrails.scan.consts import DEFAULT_POLICY
from cycode.cli.apps.ai_guardrails.scan.types import BlockReason
from cycode.cli.consts import CYCODE_CONFIGURATION_DIRECTORY
from cycode.cli.utils.path_utils import atomic_write_text, quarantine_corrupt_file
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')

GUARDRAILS_CONFIG_FILE_NAME = 'ai-guardrails-config.json'

# The matrix cell values; Report and Block share GuardrailsMode's spelling.
MODE_OFF = 'off'
MODE_REPORT = GuardrailsMode.REPORT.value
MODE_BLOCK = GuardrailsMode.BLOCK.value

_DEFAULT_TTL_SECONDS = 900

# Guardrail keys are the CLI's block-reason vocabulary. Anything else in the payload (a future
# guardrail this CLI doesn't implement) is ignored - unknown config must never fail closed.
_KNOWN_GUARDRAIL_KEYS = frozenset(
    reason.value
    for reason in (
        BlockReason.SECRETS_IN_PROMPT,
        BlockReason.SECRETS_IN_FILE,
        BlockReason.SENSITIVE_PATH,
        BlockReason.SECRETS_IN_MCP_ARGS,
    )
)

# CLI --ide names to matrix column names; identity for names not listed.
_AGENT_BY_IDE_NAME = {'claude-code': 'claude'}


def get_config_cache_path() -> Path:
    return Path.home() / CYCODE_CONFIGURATION_DIRECTORY / GUARDRAILS_CONFIG_FILE_NAME


def agent_for_ide(ide_name: Optional[str]) -> str:
    ide_name = (ide_name or '').lower()
    return _AGENT_BY_IDE_NAME.get(ide_name, ide_name)


def _default_sensitive_globs() -> list:
    return list(DEFAULT_POLICY['file_read']['deny_globs'])


@dataclass
class GuardrailConfig:
    payload: dict
    fetched_at: float
    tenant_id: Optional[str] = None
    _guardrails: dict = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._guardrails = {
            guardrail.get('key'): guardrail
            for guardrail in self.payload.get('guardrails') or []
            if guardrail.get('key') in _KNOWN_GUARDRAIL_KEYS
        }

    def mode_for(self, guardrail_key: str, ide_name: Optional[str]) -> str:
        agents = (self._guardrails.get(guardrail_key) or {}).get('agents') or {}
        return str(agents.get(agent_for_ide(ide_name), MODE_REPORT)).lower()

    def _modes_for_event(self, event_name: str, ide_name: Optional[str]) -> list:
        return [
            self.mode_for(key, ide_name)
            for key, guardrail in self._guardrails.items()
            if str(guardrail.get('event_type', '')).lower() == str(event_name).lower()
        ]

    def is_event_off(self, event_name: str, ide_name: Optional[str]) -> bool:
        """Every guardrail for this event is Off - skip the scan entirely."""
        modes = self._modes_for_event(event_name, ide_name)
        return bool(modes) and all(mode == MODE_OFF for mode in modes)

    def can_event_block(self, event_name: str, ide_name: Optional[str]) -> bool:
        """At least one guardrail for this event is in Block mode - the scan must stay synchronous."""
        return MODE_BLOCK in self._modes_for_event(event_name, ide_name)

    def sensitive_globs(self) -> list:
        settings = (self._guardrails.get(BlockReason.SENSITIVE_PATH) or {}).get('settings') or {}
        globs = settings.get('globs')
        return globs if isinstance(globs, list) and globs else _default_sensitive_globs()

    def is_expired(self) -> bool:
        ttl = self.payload.get('ttl_seconds') or _DEFAULT_TTL_SECONDS
        return time.time() - self.fetched_at > ttl

    def needs_refresh(self, tenant_id: Optional[str]) -> bool:
        """Expired, or fetched for another tenant (the user switched tenants since)."""
        return self.is_expired() or self.tenant_id != tenant_id


def apply_platform_config(policy: dict, config: Optional[GuardrailConfig], ide_name: Optional[str]) -> None:
    """Overlay the platform-owned enforcement config onto the local knobs-only policy.

    The platform is the only mode source: no cache (cold start) means the built-in defaults -
    Report everywhere with the default globs - which equal an unconfigured tenant's platform
    config, so behaviour is uniform either way. Each matrix cell lands on its own per-feature
    action, so the two FileRead guardrails (content scan vs. sensitive path) keep independent modes.
    An all-Off event never reaches here (scan_command skips it), so `enabled` stays untouched.
    """

    def cell(guardrail_key: str) -> str:
        return config.mode_for(guardrail_key, ide_name) if config is not None else MODE_REPORT

    def action(guardrail_key: str) -> str:
        return PolicyMode.BLOCK.value if cell(guardrail_key) == MODE_BLOCK else PolicyMode.WARN.value

    policy.setdefault('prompt', {})['action'] = action(BlockReason.SECRETS_IN_PROMPT)

    file_read = policy.setdefault('file_read', {})
    file_read['scan_content'] = cell(BlockReason.SECRETS_IN_FILE) != MODE_OFF
    file_read['action'] = action(BlockReason.SECRETS_IN_FILE)
    file_read['deny_globs'] = (
        (config.sensitive_globs() if config is not None else _default_sensitive_globs())
        if cell(BlockReason.SENSITIVE_PATH) != MODE_OFF
        else []
    )
    file_read['path_action'] = action(BlockReason.SENSITIVE_PATH)

    policy.setdefault('mcp', {})['action'] = action(BlockReason.SECRETS_IN_MCP_ARGS)


def save_guardrail_config(payload: dict, tenant_id: Optional[str]) -> None:
    """Persist a fetched resolved config; a failed write just leaves the previous cache in place."""
    path = get_config_cache_path()
    content = {'fetched_at': time.time(), 'tenant_id': tenant_id, 'payload': payload}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(str(path), json.dumps(content))
    except Exception as e:
        logger.debug('Failed to save guardrail config cache', exc_info=e)


def load_guardrail_config() -> Optional[GuardrailConfig]:
    """The cached platform config, or None when it is absent or corrupt (quarantined)."""
    path = get_config_cache_path()
    if not path.exists():
        return None

    try:
        with open(path, encoding='UTF-8') as file:
            content = json.load(file)
        payload = content['payload']
        if not isinstance(payload, dict):
            raise ValueError('payload is not an object')
        return GuardrailConfig(
            payload=payload, fetched_at=float(content['fetched_at']), tenant_id=content.get('tenant_id')
        )
    except Exception as e:
        logger.warning('Guardrail config cache is corrupt and will be moved aside', exc_info=e)
        quarantine_corrupt_file(str(path))
        return None
