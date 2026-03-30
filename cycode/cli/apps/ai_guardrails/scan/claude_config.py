"""Reader for ~/.claude.json configuration file.

Extracts user email and MCP server configuration from the Claude Code
global config file for use in AI guardrails scan enrichment.
"""

import json
from pathlib import Path
from typing import Optional

from cycode.logger import get_logger

logger = get_logger('AI Guardrails Claude Config')

_CLAUDE_CONFIG_PATH = Path.home() / '.claude.json'

_SERVER_TYPE_MAPPING = {
    'stdio': 'Local',
    'http': 'Remote',
}


def load_claude_config(config_path: Optional[Path] = None) -> Optional[dict]:
    """Load and parse ~/.claude.json.

    Args:
        config_path: Override path for testing. Defaults to ~/.claude.json.

    Returns:
        Parsed dict or None if file is missing or invalid.
    """
    path = config_path or _CLAUDE_CONFIG_PATH
    if not path.exists():
        logger.debug('Claude config file not found', extra={'path': str(path)})
        return None
    try:
        content = path.read_text(encoding='utf-8')
        return json.loads(content)
    except Exception as e:
        logger.debug('Failed to load Claude config file', exc_info=e)
        return None


def get_user_email(config: dict) -> Optional[str]:
    """Extract user email from Claude config.

    Reads oauthAccount.emailAddress from the config dict.
    """
    return config.get('oauthAccount', {}).get('emailAddress')


def get_mcp_servers(config: dict) -> list[dict]:
    """Extract top-level MCP servers from Claude config and map to backend DTO shape.

    Reads the top-level mcpServers dict and transforms each entry to match
    the McpServerPayloadDTO expected by ai-security-manager:
        - name: server key name
        - server_type: "Local" (stdio) or "Remote" (http)
        - command: executable command (stdio servers)
        - args: command arguments (stdio servers)
        - url: server URL (http servers)

    Returns:
        List of dicts matching McpServerPayloadDTO shape. Empty list if none found.
    """
    mcp_servers = config.get('mcpServers', {})
    if not isinstance(mcp_servers, dict):
        return []

    result = []
    for name, server_config in mcp_servers.items():
        if not isinstance(server_config, dict):
            continue

        raw_type = server_config.get('type', '')
        server_type = _SERVER_TYPE_MAPPING.get(raw_type, raw_type)

        result.append({
            'name': name,
            'server_type': server_type,
            'command': server_config.get('command'),
            'args': server_config.get('args'),
            'url': server_config.get('url'),
        })

    return result
