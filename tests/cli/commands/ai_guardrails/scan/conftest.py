import time
from typing import Optional

from cycode.cli.apps.ai_guardrails.scan.guardrail_config import GuardrailConfig


def resolved_guardrails_payload(
    prompt: str = 'Report',
    file_read: str = 'Report',
    sensitive_path: str = 'Report',
    mcp: str = 'Report',
    globs: Optional[list] = None,
) -> dict:
    """A platform resolved-config payload with the given per-guardrail modes for the cursor agent."""
    return {
        'ttl_seconds': 900,
        'guardrails': [
            {'key': 'secrets_in_prompt', 'event_type': 'Prompt', 'agents': {'cursor': prompt, 'claude': 'Block'}},
            {'key': 'secrets_in_file', 'event_type': 'FileRead', 'agents': {'cursor': file_read}},
            {
                'key': 'sensitive_path',
                'event_type': 'FileRead',
                'agents': {'cursor': sensitive_path},
                'settings': {'globs': globs if globs is not None else ['.env', 'secrets/**']},
            },
            {'key': 'secrets_in_mcp_args', 'event_type': 'McpExecution', 'agents': {'cursor': mcp}},
        ],
    }


def platform_config(fetched_at: Optional[float] = None, **modes: str) -> GuardrailConfig:
    """A cached platform config; keyword args are the per-guardrail modes (see resolved_guardrails_payload)."""
    return GuardrailConfig(
        payload=resolved_guardrails_payload(**modes),
        fetched_at=time.time() if fetched_at is None else fetched_at,
    )
