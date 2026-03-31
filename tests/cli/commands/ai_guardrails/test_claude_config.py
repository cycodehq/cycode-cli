"""Tests for Claude Code config file reader."""

import json
from pathlib import Path

from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.scan.claude_config import get_user_email, load_claude_config


def test_load_claude_config_valid(fs: FakeFilesystem) -> None:
    """Test loading a valid ~/.claude.json file."""
    config = {'oauthAccount': {'emailAddress': 'user@example.com'}}
    config_path = Path.home() / '.claude.json'
    fs.create_file(config_path, contents=json.dumps(config))

    result = load_claude_config(config_path)
    assert result == config


def test_load_claude_config_missing_file(fs: FakeFilesystem) -> None:
    """Test loading when ~/.claude.json does not exist."""
    fs.create_dir(Path.home())
    config_path = Path.home() / '.claude.json'

    result = load_claude_config(config_path)
    assert result is None


def test_load_claude_config_corrupt_file(fs: FakeFilesystem) -> None:
    """Test loading when ~/.claude.json contains invalid JSON."""
    config_path = Path.home() / '.claude.json'
    fs.create_file(config_path, contents='not valid json {{{')

    result = load_claude_config(config_path)
    assert result is None


def test_get_user_email_present() -> None:
    """Test extracting email when oauthAccount.emailAddress exists."""
    config = {'oauthAccount': {'emailAddress': 'user@example.com'}}
    assert get_user_email(config) == 'user@example.com'


def test_get_user_email_missing_oauth_account() -> None:
    """Test extracting email when oauthAccount key is missing."""
    config = {'someOtherKey': 'value'}
    assert get_user_email(config) is None


def test_get_user_email_missing_email_address() -> None:
    """Test extracting email when oauthAccount exists but emailAddress is missing."""
    config = {'oauthAccount': {'someOtherField': 'value'}}
    assert get_user_email(config) is None
