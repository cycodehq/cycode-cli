"""Tests for the MCP server authorization status cache."""

import time
from pathlib import Path
from typing import Optional

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.scan.mcp_server_status import (
    McpServerAuthorizationStatus,
    McpServerStatuses,
    get_mcp_server_statuses_cache_path,
    is_enforced,
    load_mcp_server_statuses,
    parse_status,
    save_mcp_server_statuses,
)

_AUTHORIZED = McpServerAuthorizationStatus.AUTHORIZED
_UNREVIEWED = McpServerAuthorizationStatus.UNREVIEWED
_UNAUTHORIZED = McpServerAuthorizationStatus.UNAUTHORIZED


@pytest.fixture(autouse=True)
def _fake_home(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('HOME', '/home/testuser')
    fs.create_dir('/home/testuser')


def _statuses(*rows: tuple[str, str]) -> McpServerStatuses:
    return McpServerStatuses(
        servers=[{'alias': alias, 'normalized_id': f'id:{alias}', 'status': status} for alias, status in rows],
        fetched_at=time.time(),
    )


def test_cache_file_sits_next_to_the_guardrail_config() -> None:
    assert get_mcp_server_statuses_cache_path() == Path.home() / '.cycode' / 'ai-guardrails-mcp-servers.json'


@pytest.mark.parametrize(
    ('raw', 'expected'),
    [
        ('Authorized', _AUTHORIZED),
        ('unauthorized', _UNAUTHORIZED),
        ('UNREVIEWED', _UNREVIEWED),
        ('Pending', _UNREVIEWED),
        (None, _UNREVIEWED),
    ],
)
def test_parse_status_is_case_insensitive_and_unknown_reads_unreviewed(
    raw: Optional[str], expected: McpServerAuthorizationStatus
) -> None:
    assert parse_status(raw) == expected


@pytest.mark.parametrize(
    ('status', 'enforce_on', 'expected'),
    [
        (_UNAUTHORIZED, 'unauthorized', True),
        (_UNREVIEWED, 'unauthorized', False),
        (_AUTHORIZED, 'unauthorized', False),
        (None, 'unauthorized', False),
        (_UNAUTHORIZED, 'not_authorized', True),
        (_UNREVIEWED, 'not_authorized', True),
        (None, 'not_authorized', True),
        (_AUTHORIZED, 'not_authorized', False),
    ],
)
def test_is_enforced(status: Optional[McpServerAuthorizationStatus], enforce_on: str, expected: bool) -> None:
    assert is_enforced(status, enforce_on) is expected


def test_match_is_case_insensitive_and_returns_the_stored_alias() -> None:
    match = _statuses(('GitHub', 'Unauthorized')).match('github')

    assert match is not None
    assert match.alias == 'GitHub'
    assert match.status == _UNAUTHORIZED


def test_match_unknown_alias_returns_none() -> None:
    assert _statuses(('github', 'Authorized')).match('notion') is None


def test_the_most_restrictive_status_wins_for_one_alias() -> None:
    statuses = _statuses(('github', 'Authorized'), ('github', 'Unauthorized'), ('github', 'Unreviewed'))
    assert statuses.match('github').status == _UNAUTHORIZED

    statuses = _statuses(('notion', 'Authorized'), ('Notion', 'Unreviewed'))
    assert statuses.match('notion').status == _UNREVIEWED


def test_match_normalized_name() -> None:
    # Claude Code turns characters outside [A-Za-z0-9_-] into '_' in tool names.
    match = _statuses(('my.server', 'Unauthorized')).match('my_server')

    assert match is not None
    assert match.alias == 'my.server'


def test_match_plugin_namespaced_name_by_longest_server_suffix() -> None:
    statuses = _statuses(('sentry', 'Authorized'), ('dev_sentry', 'Unauthorized'), ('other', 'Unauthorized'))

    match = statuses.match('plugin_cycode-dev_sentry')
    assert match is not None
    assert match.alias == 'sentry'

    match = statuses.match('plugin_cycode_dev_sentry')
    assert match is not None
    assert match.alias == 'dev_sentry'

    assert statuses.match('plugin_cycode-dev_unknown') is None


def test_rows_without_an_alias_are_ignored() -> None:
    statuses = McpServerStatuses(servers=[{'status': 'Unauthorized'}, 'garbage', {'alias': ''}], fetched_at=time.time())
    assert statuses.match('') is None


def test_save_and_load_round_trip() -> None:
    save_mcp_server_statuses([{'alias': 'github', 'status': 'Unauthorized'}], 'tenant-a', ttl_seconds=60)

    statuses = load_mcp_server_statuses()

    assert statuses is not None
    assert statuses.match('github').status == _UNAUTHORIZED
    assert statuses.ttl_seconds == 60
    assert statuses.needs_refresh('tenant-a') is False
    assert statuses.needs_refresh('tenant-b') is True


def test_expired_cache_needs_refresh() -> None:
    statuses = McpServerStatuses(servers=[], fetched_at=time.time() - 10_000, tenant_id='tenant-a')
    assert statuses.needs_refresh('tenant-a') is True


def test_load_missing_cache_returns_none() -> None:
    assert load_mcp_server_statuses() is None


def test_corrupt_cache_is_quarantined(fs: FakeFilesystem) -> None:
    path = get_mcp_server_statuses_cache_path()
    fs.create_file(str(path), contents='{"servers": {}}')

    assert load_mcp_server_statuses() is None
    assert not path.exists()
    assert Path(f'{path}.corrupt').exists()
