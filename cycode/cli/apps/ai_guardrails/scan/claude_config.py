"""Reader for Claude Code configuration file.

Extracts user email from the Claude Code global config file
for use in AI guardrails scan enrichment.

Config file locations:
- macOS/Linux: ~/.claude.json
- Windows: %APPDATA%/Claude/claude.json (fallback: ~/.claude.json)
"""

import json
import os
import platform
from pathlib import Path
from typing import Optional

from cycode.logger import get_logger

logger = get_logger('AI Guardrails Claude Config')

_CLAUDE_CONFIG_FILENAME = 'claude.json'


def _get_claude_config_path() -> Path:
    """Get Claude config file path based on platform.

    Claude Code uses ~/.claude.json on macOS/Linux.
    On Windows, checks %APPDATA%/Claude/claude.json first,
    then falls back to ~/.claude.json.
    """
    if platform.system() == 'Windows':
        appdata = os.environ.get('APPDATA')
        if appdata:
            appdata_path = Path(appdata) / 'Claude' / _CLAUDE_CONFIG_FILENAME
            if appdata_path.exists():
                return appdata_path

    return Path.home() / f'.{_CLAUDE_CONFIG_FILENAME}'


_CLAUDE_CONFIG_PATH = _get_claude_config_path()


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
