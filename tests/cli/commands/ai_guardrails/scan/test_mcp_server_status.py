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
    ('status', 'expected'),
    [
        (_UNAUTHORIZED, True),
        (_UNREVIEWED, False),
        (_AUTHORIZED, False),
        (None, False),
    ],
)
def test_is_enforced(status: Optional[McpServerAuthorizationStatus], expected: bool) -> None:
    assert is_enforced(status) is expected


def test_status_of_is_case_insensitive() -> None:
    assert _statuses(('GitHub', 'Unauthorized')).status_of('github') == _UNAUTHORIZED


def test_status_of_unknown_alias_returns_none() -> None:
    assert _statuses(('github', 'Authorized')).status_of('notion') is None


def test_the_most_restrictive_status_wins_for_one_alias() -> None:
    statuses = _statuses(('github', 'Authorized'), ('github', 'Unauthorized'), ('github', 'Unreviewed'))
    assert statuses.status_of('github') == _UNAUTHORIZED

    statuses = _statuses(('notion', 'Authorized'), ('Notion', 'Unreviewed'))
    assert statuses.status_of('notion') == _UNREVIEWED


def test_rows_without_an_alias_are_ignored() -> None:
    statuses = McpServerStatuses(servers=[{'status': 'Unauthorized'}, 'garbage', {'alias': ''}], fetched_at=time.time())
    assert statuses.status_of('') is None


def test_save_and_load_round_trip() -> None:
    save_mcp_server_statuses([{'alias': 'github', 'status': 'Unauthorized'}], 'tenant-a', ttl_seconds=60)

    statuses = load_mcp_server_statuses()

    assert statuses is not None
    assert statuses.status_of('github') == _UNAUTHORIZED
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
