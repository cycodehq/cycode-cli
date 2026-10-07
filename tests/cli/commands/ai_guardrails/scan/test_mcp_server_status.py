"""Tests for the MCP server authorization status cache."""

import json
import time
from pathlib import Path
from typing import Optional

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.apps.ai_guardrails.scan.mcp_server_status import (
    McpServerStatuses,
    get_mcp_server_statuses_cache_path,
    is_enforced,
    load_mcp_server_statuses,
    save_mcp_server_statuses,
)
from cycode.cyclient.models import McpServerAuthorizationStatus, McpServerStatus

_AUTHORIZED = McpServerAuthorizationStatus.AUTHORIZED
_UNREVIEWED = McpServerAuthorizationStatus.UNREVIEWED
_UNAUTHORIZED = McpServerAuthorizationStatus.UNAUTHORIZED


@pytest.fixture(autouse=True)
def _fake_home(fs: FakeFilesystem, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('HOME', '/home/testuser')
    fs.create_dir('/home/testuser')


def _statuses(*rows: tuple[str, str]) -> McpServerStatuses:
    return McpServerStatuses(
        servers=[
            McpServerStatus(alias, f'id:{alias}', McpServerAuthorizationStatus.parse(status)) for alias, status in rows
        ],
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
    assert McpServerAuthorizationStatus.parse(raw) == expected


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
    statuses = McpServerStatuses(
        servers=[McpServerStatus(status=_UNAUTHORIZED), McpServerStatus(alias='', status=_UNAUTHORIZED)],
        fetched_at=time.time(),
    )
    assert statuses.status_of('') is None


def test_save_and_load_round_trip() -> None:
    save_mcp_server_statuses([McpServerStatus('github', 'pkg:gh', _UNAUTHORIZED)], 'tenant-a', ttl_seconds=60)

    statuses = load_mcp_server_statuses()

    assert statuses is not None
    assert statuses.status_of('github') == _UNAUTHORIZED
    assert statuses.servers == [McpServerStatus('github', 'pkg:gh', _UNAUTHORIZED)]
    assert statuses.tenant_id == 'tenant-a'
    assert statuses.ttl_seconds == 60


def test_saved_cache_keeps_the_file_format() -> None:
    save_mcp_server_statuses([McpServerStatus('github', 'pkg:gh', _UNAUTHORIZED)], 'tenant-a', ttl_seconds=60)

    content = json.loads(get_mcp_server_statuses_cache_path().read_text(encoding='UTF-8'))

    assert set(content) == {'servers', 'fetched_at', 'tenant_id', 'ttl_seconds'}
    assert content['servers'] == [{'alias': 'github', 'normalized_id': 'pkg:gh', 'status': 'Unauthorized'}]


def test_load_ignores_unknown_fields_and_reads_unknown_statuses_as_unreviewed(fs: FakeFilesystem) -> None:
    fs.create_file(
        str(get_mcp_server_statuses_cache_path()),
        contents=json.dumps(
            {'fetched_at': time.time(), 'future': 1, 'servers': [{'alias': 'github', 'status': 'Pending', 'x': 1}]}
        ),
    )

    statuses = load_mcp_server_statuses()

    assert statuses is not None
    assert statuses.status_of('github') == _UNREVIEWED


def test_load_missing_cache_returns_none() -> None:
    assert load_mcp_server_statuses() is None


@pytest.mark.parametrize(
    'contents',
    ['{"servers": {}, "fetched_at": 1}', '{"servers": []}', '{"servers": ["garbage"], "fetched_at": 1}', 'not json'],
)
def test_corrupt_cache_is_quarantined(contents: str, fs: FakeFilesystem) -> None:
    path = get_mcp_server_statuses_cache_path()
    fs.create_file(str(path), contents=contents)

    assert load_mcp_server_statuses() is None
    assert not path.exists()
    assert Path(f'{path}.corrupt').exists()
