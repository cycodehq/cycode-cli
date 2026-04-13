"""Reader for ~/.claude.json configuration file.

Extracts user email from the Claude Code global config file
for use in AI guardrails scan enrichment.
"""

import json
from pathlib import Path
from typing import Optional

from cycode.logger import get_logger

logger = get_logger('AI Guardrails Claude Config')

_CLAUDE_CONFIG_PATH = Path.home() / '.claude.json'


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


def get_mcp_servers(config: dict) -> Optional[dict]:
    """Extract MCP servers from Claude config.

    Reads mcpServers from the config dict.
    """
    return config.get('mcpServers')
