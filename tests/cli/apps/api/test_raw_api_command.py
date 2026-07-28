"""Tests for the raw API passthrough command (`cycode platform api`)."""

import contextlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

import click
import pytest
import responses
from typer.testing import CliRunner

from cycode.cli.app import app
from cycode.cli.apps.api.raw_api_command import (
    _parse_headers,
    _parse_query,
    _read_body,
    _validate_path,
)
from tests.conftest import CLI_ENV_VARS

if TYPE_CHECKING:
    from click.testing import Result

    from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient


# The on-close update check requests PyPI (VersionChecker.PYPI_REQUEST_TIMEOUT = 1),
# which would otherwise show up in responses.calls and pollute request assertions.
_ROOT_ARGS = ['--no-update-notifier']


def _all_output(result: 'Result') -> str:
    """Combine stdout and stderr.

    Click 8.1 mixes stderr into `output`, while Click 8.2+ captures it separately.
    """
    parts = [result.output]
    with contextlib.suppress(AttributeError, ValueError):
        parts.append(result.stderr)  # raises when stderr was mixed into output already

    return ''.join(parts)


def _find_call(url: str) -> responses.Call:
    """Find the recorded request for a URL, ignoring auth and version-check traffic."""
    matching = [call for call in responses.calls if call.request.url.split('?')[0] == url]
    assert matching, f'no recorded request for {url}. Recorded: {[c.request.url for c in responses.calls]}'
    return matching[-1]


# --- _validate_path ---


def test_validate_path_strips_leading_slash() -> None:
    assert _validate_path('/v4/projects') == 'v4/projects'


@pytest.mark.parametrize('path', ['v4/projects', 'api/v4/projects', 'v4/api-docs/cycode-api-swagger.json'])
def test_validate_path_accepts_versioned_api_path(path: str) -> None:
    assert _validate_path(path) == path


@pytest.mark.parametrize(
    'path',
    [
        'https://evil.example/v4/x',
        'http://localhost/v4/x',
        '//evil.example/v4/x',
        'v4/projects and more',
        'projects',
        'v4',
        'v4/',
        'api/projects',
        'v1/auth/api-token',
    ],
)
def test_validate_path_rejects_non_api_path(path: str) -> None:
    with pytest.raises(click.ClickException):
        _validate_path(path)


# --- _parse_query ---


def test_parse_query_single_pair() -> None:
    assert _parse_query(('page-size=5',)) == {'page-size': '5'}


def test_parse_query_value_with_equals_sign() -> None:
    assert _parse_query(('filter=a=b',)) == {'filter': 'a=b'}


def test_parse_query_empty_value() -> None:
    assert _parse_query(('name=',)) == {'name': ''}


def test_parse_query_repeated_key_collapses_to_list() -> None:
    assert _parse_query(('severity=High', 'severity=Critical', 'severity=Low')) == {
        'severity': ['High', 'Critical', 'Low']
    }


@pytest.mark.parametrize('item', ['page-size', '=5', ''])
def test_parse_query_invalid_pair(item: str) -> None:
    with pytest.raises(click.ClickException):
        _parse_query((item,))


# --- _parse_headers ---


def test_parse_headers_strips_whitespace() -> None:
    assert _parse_headers(('X-Foo:  bar ',)) == {'X-Foo': 'bar'}


def test_parse_headers_value_with_colon() -> None:
    assert _parse_headers(('X-Url: https://example.com',)) == {'X-Url': 'https://example.com'}


@pytest.mark.parametrize('item', ['Authorization: Bearer x', 'authorization: Bearer x'])
def test_parse_headers_rejects_authorization(item: str) -> None:
    with pytest.raises(click.ClickException):
        _parse_headers((item,))


@pytest.mark.parametrize('item', ['X-Foo', ': bar'])
def test_parse_headers_invalid_pair(item: str) -> None:
    with pytest.raises(click.ClickException):
        _parse_headers((item,))


# --- _read_body ---


def test_read_body_inline_json() -> None:
    assert _read_body('{"a": 1}') == {'a': 1}


def test_read_body_from_file(tmp_path: Path) -> None:
    body_file = tmp_path.joinpath('body.json')
    body_file.write_text('{"a": [1, 2]}', encoding='utf-8')

    assert _read_body(f'@{body_file}') == {'a': [1, 2]}


def test_read_body_missing_file(tmp_path: Path) -> None:
    with pytest.raises(click.ClickException):
        _read_body(f'@{tmp_path.joinpath("nope.json")}')


def test_read_body_invalid_json() -> None:
    with pytest.raises(click.ClickException):
        _read_body('not json')


# --- end-to-end ---


@responses.activate
def test_raw_api_get_prints_json(
    token_based_client: 'CycodeTokenBasedClient', api_token_response: responses.Response
) -> None:
    # The OpenAPI spec URL is deliberately not mocked: `platform api` must not fetch the spec
    responses.add(api_token_response)
    responses.add(
        responses.Response(
            method=responses.GET,
            url=f'{token_based_client.api_url}/v4/projects',
            json={'items': [{'id': '1'}]},
            status=200,
        )
    )

    result = CliRunner().invoke(app, [*_ROOT_ARGS, 'platform', 'api', 'get', 'v4/projects'], env=CLI_ENV_VARS)

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {'items': [{'id': '1'}]}


@responses.activate
def test_raw_api_get_sends_query_params(
    token_based_client: 'CycodeTokenBasedClient', api_token_response: responses.Response
) -> None:
    responses.add(api_token_response)
    responses.add(
        responses.Response(
            method=responses.GET,
            url=f'{token_based_client.api_url}/v4/violations',
            json={'items': []},
            status=200,
        )
    )

    args = [*_ROOT_ARGS, 'platform', 'api', 'get', '/v4/violations', '-q', 'severity=High', '-q', 'severity=Critical']
    result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

    assert result.exit_code == 0, result.output
    request_url = _find_call(f'{token_based_client.api_url}/v4/violations').request.url
    assert 'severity=High' in request_url
    assert 'severity=Critical' in request_url


@responses.activate
def test_raw_api_post_sends_body(
    token_based_client: 'CycodeTokenBasedClient', api_token_response: responses.Response
) -> None:
    responses.add(api_token_response)
    responses.add(
        responses.Response(
            method=responses.POST,
            url=f'{token_based_client.api_url}/v4/sbom/import',
            json={'id': 'abc'},
            status=200,
        )
    )

    args = [*_ROOT_ARGS, 'platform', 'api', 'post', 'v4/sbom/import', '-d', '{"name": "test"}']
    result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

    assert result.exit_code == 0, result.output
    request = _find_call(f'{token_based_client.api_url}/v4/sbom/import').request
    assert json.loads(request.body) == {'name': 'test'}


@responses.activate
def test_raw_api_sends_additional_header(
    token_based_client: 'CycodeTokenBasedClient', api_token_response: responses.Response
) -> None:
    responses.add(api_token_response)
    responses.add(
        responses.Response(
            method=responses.GET,
            url=f'{token_based_client.api_url}/v4/projects',
            json={},
            status=200,
        )
    )

    args = [*_ROOT_ARGS, 'platform', 'api', 'get', 'v4/projects', '-H', 'X-Foo: bar']
    result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

    assert result.exit_code == 0, result.output
    request_headers = _find_call(f'{token_based_client.api_url}/v4/projects').request.headers
    assert request_headers['X-Foo'] == 'bar'
    assert request_headers['Authorization'].startswith('Bearer ')


@responses.activate
def test_raw_api_put_reads_body_from_stdin(
    token_based_client: 'CycodeTokenBasedClient', api_token_response: responses.Response
) -> None:
    responses.add(api_token_response)
    responses.add(
        responses.Response(
            method=responses.PUT,
            url=f'{token_based_client.api_url}/v4/some/resource',
            json={},
            status=200,
        )
    )

    args = [*_ROOT_ARGS, 'platform', 'api', 'put', 'v4/some/resource', '-d', '-']
    result = CliRunner().invoke(app, args, env=CLI_ENV_VARS, input='{"from": "stdin"}')

    assert result.exit_code == 0, result.output
    request = _find_call(f'{token_based_client.api_url}/v4/some/resource').request
    assert json.loads(request.body) == {'from': 'stdin'}


@responses.activate
def test_raw_api_timeout_option_is_forwarded(
    token_based_client: 'CycodeTokenBasedClient', api_token_response: responses.Response
) -> None:
    responses.add(api_token_response)
    responses.add(
        responses.Response(
            method=responses.GET,
            url=f'{token_based_client.api_url}/v4/projects',
            json={},
            status=200,
        )
    )

    args = [*_ROOT_ARGS, 'platform', 'api', 'get', 'v4/projects', '--timeout', '7']
    result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

    assert result.exit_code == 0, result.output
    request = _find_call(f'{token_based_client.api_url}/v4/projects').request
    assert request.req_kwargs['timeout'] == 7


@responses.activate
def test_raw_api_non_json_response_prints_text(
    token_based_client: 'CycodeTokenBasedClient', api_token_response: responses.Response
) -> None:
    responses.add(api_token_response)
    responses.add(
        responses.Response(
            method=responses.GET,
            url=f'{token_based_client.api_url}/v4/plain',
            body='plain text',
            status=200,
        )
    )

    result = CliRunner().invoke(app, [*_ROOT_ARGS, 'platform', 'api', 'get', 'v4/plain'], env=CLI_ENV_VARS)

    assert result.exit_code == 0, result.output
    assert 'plain text' in result.output


@responses.activate
def test_raw_api_http_error_exits_non_zero(
    token_based_client: 'CycodeTokenBasedClient', api_token_response: responses.Response
) -> None:
    responses.add(api_token_response)
    responses.add(
        responses.Response(
            method=responses.GET,
            url=f'{token_based_client.api_url}/v4/does-not-exist',
            json={'message': 'not found'},
            status=404,
        )
    )

    result = CliRunner().invoke(app, [*_ROOT_ARGS, 'platform', 'api', 'get', 'v4/does-not-exist'], env=CLI_ENV_VARS)

    assert result.exit_code != 0
    assert '404' in _all_output(result)


@pytest.mark.parametrize('path', ['https://evil.example/v4/x', 'projects'])
def test_raw_api_rejects_non_api_path(path: str) -> None:
    result = CliRunner().invoke(app, [*_ROOT_ARGS, 'platform', 'api', 'get', path], env=CLI_ENV_VARS)

    assert result.exit_code != 0
    assert 'must be a versioned API path' in _all_output(result)


def test_raw_api_rejects_data_with_get() -> None:
    args = [*_ROOT_ARGS, 'platform', 'api', 'get', 'v4/projects', '-d', '{}']
    result = CliRunner().invoke(app, args, env=CLI_ENV_VARS)

    assert result.exit_code != 0
    assert '--data is not supported' in _all_output(result)


def test_raw_api_rejects_unsupported_method() -> None:
    result = CliRunner().invoke(app, [*_ROOT_ARGS, 'platform', 'api', 'delete', 'v4/projects'], env=CLI_ENV_VARS)

    assert result.exit_code != 0
