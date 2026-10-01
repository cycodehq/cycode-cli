"""Tests for the platform guardrail config cache."""

import time
from pathlib import Path

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.scan.consts import DEFAULT_SENSITIVE_PATH_GLOBS
from cycode.cli.apps.ai_guardrails.scan.guardrail_config import (
    GuardrailConfig,
    apply_platform_config,
    get_config_cache_path,
    load_guardrail_config,
    save_guardrail_config,
)
from tests.cli.commands.ai_guardrails.scan.conftest import platform_config as _config
from tests.cli.commands.ai_guardrails.scan.conftest import resolved_guardrails_payload as _payload


@pytest.fixture(autouse=True)
def _fake_home(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('HOME', '/home/testuser')
    fs.create_dir('/home/testuser')


# --- cache file ---


def test_save_and_load_round_trip() -> None:
    save_guardrail_config(_payload(), 'tenant-a')

    config = load_guardrail_config()

    assert config is not None
    assert config.is_expired() is False
    assert config.tenant_id == 'tenant-a'
    assert config.needs_refresh('tenant-a') is False
    # Switching tenants invalidates the cache even while it is still fresh.
    assert config.needs_refresh('tenant-b') is True


def test_load_missing_cache_returns_none() -> None:
    assert load_guardrail_config() is None


def test_corrupt_cache_is_quarantined(fs: FakeFilesystem) -> None:
    path = get_config_cache_path()
    fs.create_file(str(path), contents='not json {')

    assert load_guardrail_config() is None
    assert not path.exists()
    assert Path(f'{path}.corrupt').exists()


def test_expired_cache_detected() -> None:
    config = GuardrailConfig(payload=_payload(), fetched_at=time.time() - 10_000, tenant_id='tenant-a')
    assert config.is_expired() is True
    assert config.needs_refresh('tenant-a') is True


# --- lookups ---


def test_cells_are_read_by_ide_name() -> None:
    config = _config()
    # cursor column is Report; the claude-code column is Block.
    assert config.can_event_block('Prompt', 'claude-code') is True
    assert config.can_event_block('Prompt', 'Claude-Code') is True
    assert config.can_event_block('Prompt', 'cursor') is False


def test_event_off_requires_every_guardrail_off() -> None:
    partially_off = _config(file_read='Off', sensitive_path='Report')
    assert partially_off.is_event_off('FileRead', 'cursor') is False

    fully_off = _config(file_read='Off', sensitive_path='Off')
    assert fully_off.is_event_off('FileRead', 'cursor') is True


def test_unknown_guardrail_keys_are_ignored() -> None:
    payload = _payload()
    # A future guardrail this CLI doesn't implement must never affect decisions (fail-open).
    payload['guardrails'].append(
        {'key': 'future_guardrail', 'event_type': 'McpExecution', 'agents': {'cursor': 'Block'}}
    )
    config = GuardrailConfig(payload=payload, fetched_at=time.time())

    assert config.can_event_block('McpExecution', 'cursor') is False


def test_missing_agent_defaults_to_report() -> None:
    config = _config()
    assert config.can_event_block('Prompt', 'codex') is False
    assert config.is_event_off('Prompt', 'codex') is False


# --- platform overlay ---


def test_apply_platform_config_without_cache_uses_report_defaults() -> None:
    policy: dict = {'fail_open': True}

    apply_platform_config(policy, None, 'cursor')

    assert policy['prompt']['action'] == 'warn'
    assert policy['file_read']['action'] == 'warn'
    assert policy['file_read']['path_action'] == 'warn'
    assert policy['mcp']['action'] == 'warn'
    assert policy['file_read']['deny_globs'] == DEFAULT_SENSITIVE_PATH_GLOBS


def test_apply_platform_config_block_cell_sets_block_action() -> None:
    policy: dict = {}

    apply_platform_config(policy, _config(prompt='Block'), 'cursor')

    assert policy['prompt']['action'] == 'block'
    assert policy['mcp']['action'] == 'warn'


def test_apply_platform_config_file_read_cells_keep_independent_actions() -> None:
    # Content scan and sensitive path share the FileRead event but are separate matrix cells.
    policy: dict = {}
    apply_platform_config(policy, _config(file_read='Block', sensitive_path='Report'), 'cursor')
    assert policy['file_read']['action'] == 'block'
    assert policy['file_read']['path_action'] == 'warn'

    policy = {}
    apply_platform_config(policy, _config(file_read='Report', sensitive_path='Block'), 'cursor')
    assert policy['file_read']['action'] == 'warn'
    assert policy['file_read']['path_action'] == 'block'


def test_apply_platform_config_off_cells_disable_subfeatures() -> None:
    policy: dict = {}
    config = _config(file_read='Off', sensitive_path='Report')

    apply_platform_config(policy, config, 'cursor')

    # Content scan off, path matching still on with the platform globs.
    assert policy['file_read']['scan_content'] is False
    assert policy['file_read']['deny_globs'] == ['.env', 'secrets/**']


def test_apply_platform_config_sensitive_path_off_clears_globs() -> None:
    policy: dict = {}
    config = _config(sensitive_path='Off')

    apply_platform_config(policy, config, 'cursor')

    assert policy['file_read']['deny_globs'] == []
    assert policy['file_read']['scan_content'] is True


# --- unauthorized MCP server guardrail ---


def test_unauthorized_mcp_server_defaults_to_off() -> None:
    # Unlike the other guardrails: a missing entry, or a missing agent cell, must not enable it.
    missing_entry = _config()
    assert missing_entry.mode_for('unauthorized_mcp_server', 'cursor') == 'off'
    assert missing_entry.is_off_for_every_agent('unauthorized_mcp_server') is True

    missing_cell = _config(mcp_server='Block')
    assert missing_cell.mode_for('unauthorized_mcp_server', 'codex') == 'off'
    assert missing_cell.can_event_block('McpExecution', 'codex') is False


def test_unauthorized_mcp_server_block_makes_the_event_blockable() -> None:
    config = _config(mcp_server='Block')

    assert config.can_event_block('McpExecution', 'cursor') is True
    assert config.is_off_for_every_agent('unauthorized_mcp_server') is False


def test_mcp_event_is_off_only_when_both_mcp_guardrails_are_off() -> None:
    assert _config(mcp='Off').is_event_off('McpExecution', 'cursor') is True
    assert _config(mcp='Off', mcp_server='Off').is_event_off('McpExecution', 'cursor') is True
    assert _config(mcp='Off', mcp_server='Report').is_event_off('McpExecution', 'cursor') is False


@pytest.mark.parametrize(
    ('enforce_on', 'expected'),
    [
        ('unauthorized', 'unauthorized'),
        ('not_authorized', 'not_authorized'),
        ('Not_Authorized', 'not_authorized'),
        ('something_new', 'unauthorized'),
        ('', 'unauthorized'),
    ],
)
def test_mcp_server_enforce_on(enforce_on: str, expected: str) -> None:
    assert _config(mcp_server='Report', enforce_on=enforce_on).mcp_server_enforce_on() == expected


def test_apply_platform_config_without_cache_leaves_the_mcp_server_check_off() -> None:
    policy: dict = {}

    apply_platform_config(policy, None, 'cursor')

    assert policy['mcp']['check_server'] is False
    assert policy['mcp']['scan_args'] is True
    assert policy['mcp']['server_enforce_on'] == 'unauthorized'


def test_apply_platform_config_mcp_server_cells() -> None:
    policy: dict = {}
    apply_platform_config(policy, _config(mcp='Off', mcp_server='Block', enforce_on='not_authorized'), 'cursor')

    assert policy['mcp']['scan_args'] is False
    assert policy['mcp']['check_server'] is True
    assert policy['mcp']['server_action'] == 'block'
    assert policy['mcp']['server_enforce_on'] == 'not_authorized'

    policy = {}
    apply_platform_config(policy, _config(mcp_server='Report'), 'cursor')

    assert policy['mcp']['check_server'] is True
    assert policy['mcp']['server_action'] == 'warn'
    assert policy['mcp']['action'] == 'warn'
