"""Reader for ~/.cursor/mcp.json configuration file.

Extracts MCP server definitions from the Cursor global config file
for use in AI guardrails session-context reporting.
"""

import json
from pathlib import Path
from typing import Optional

from cycode.logger import get_logger

logger = get_logger('AI Guardrails Cursor Config')

_CURSOR_MCP_CONFIG_PATH = Path.home() / '.cursor' / 'mcp.json'


def load_cursor_config(config_path: Optional[Path] = None) -> Optional[dict]:
    """Load and parse ~/.cursor/mcp.json.

    Args:
        config_path: Override path for testing. Defaults to ~/.cursor/mcp.json.

    Returns:
        Parsed dict or None if file is missing or invalid.
    """
    path = config_path or _CURSOR_MCP_CONFIG_PATH
    if not path.exists():
        logger.debug('Cursor MCP config file not found', extra={'path': str(path)})
        return None
    try:
        content = path.read_text(encoding='utf-8')
        return json.loads(content)
    except Exception as e:
        logger.debug('Failed to load Cursor MCP config file', exc_info=e)
        return None
