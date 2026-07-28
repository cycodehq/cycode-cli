"""Raw REST passthrough: `cycode platform api <METHOD> <PATH>`.

Lets scripts call any Cycode REST endpoint without handling credentials themselves.
The CLI resolves credentials (client id/secret or OIDC, from flags, environment
variables, or `cycode auth`), mints and refreshes the access token, and prints the
response body. Tokens and secrets are never printed.
"""

import json
import re
import sys
from typing import TYPE_CHECKING, Any, Optional, Union

import click

from cycode.logger import get_logger

if TYPE_CHECKING:
    from requests import Response

logger = get_logger('Raw API Command')

_SUPPORTED_METHODS = ('get', 'post', 'put')
_METHODS_WITH_BODY = ('post', 'put')
# Allowlist: a versioned API path such as `v4/projects` or `api/v4/auth/api-token`.
# Anything else (full URLs, protocol-relative paths, paths with whitespace) is rejected.
_API_PATH_RE = re.compile(r'^(api/)?v4/\S+$')

_HELP = """[BETA] Send a raw authenticated request to the Cycode API.

METHOD is one of get, post, put. PATH is an API path such as `v4/projects`
(a leading slash is optional).

Credentials come from the CLI: `cycode auth`, the CYCODE_CLIENT_ID/CYCODE_CLIENT_SECRET
(or CYCODE_ID_TOKEN) environment variables, or the global `--client-id`/`--client-secret`/
`--id-token` options. Your credentials and access token are never printed.

\b
Examples:
  cycode platform api get v4/projects -q page-size=5
  cycode platform api get v4/violations -q severity=High -q severity=Critical
  cycode platform api post v4/sbom/import -d @body.json
  cat body.json | cycode platform api put v4/some/resource -d -
"""


def _validate_path(path: str) -> str:
    """Validate that PATH is a versioned API path, so credentials only reach the configured Cycode host."""
    url_path = path.lstrip('/')
    if not _API_PATH_RE.match(url_path):
        raise click.ClickException(f'PATH must be a versioned API path such as `v4/projects`, not `{path}`.')

    return url_path


def _parse_query(query: tuple[str, ...]) -> dict[str, Union[str, list[str]]]:
    """Parse repeatable `key=value` pairs. Repeated keys collapse into a list."""
    params: dict[str, Union[str, list[str]]] = {}
    for item in query:
        key, sep, value = item.partition('=')
        if not sep or not key:
            raise click.ClickException(f'Invalid query parameter "{item}". Expected format: key=value')

        if key in params:
            existing = params[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                params[key] = [existing, value]
        else:
            params[key] = value

    return params


def _parse_headers(header: tuple[str, ...]) -> dict[str, str]:
    """Parse repeatable `Key: Value` pairs."""
    headers: dict[str, str] = {}
    for item in header:
        key, sep, value = item.partition(':')
        key = key.strip()
        if not sep or not key:
            raise click.ClickException(f'Invalid header "{item}". Expected format: "Key: Value"')

        if key.lower() == 'authorization':
            raise click.ClickException('The Authorization header is managed by the CLI and cannot be overridden.')

        headers[key] = value.strip()

    return headers


def _read_body(data: str) -> Any:
    """Read the request body from an inline JSON string, `@file`, or `-` (stdin)."""
    if data == '-':
        raw = sys.stdin.read()
        source = 'stdin'
    elif data.startswith('@'):
        file_path = data[1:]
        try:
            with open(file_path, encoding='utf-8') as f:
                raw = f.read()
        except OSError as e:
            raise click.ClickException(f'Could not read request body file "{file_path}": {e}') from e
        source = file_path
    else:
        raw = data
        source = 'the --data value'

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise click.ClickException(f'Could not parse JSON from {source}: {e}') from e


def _echo_response_body(response: 'Response') -> None:
    try:
        click.echo(json.dumps(response.json(), indent=2))
    except ValueError:
        # Not a JSON body (empty response, plain text, file download, etc.)
        click.echo(response.text)


def _callback(
    method: str,
    path: str,
    query: tuple[str, ...],
    header: tuple[str, ...],
    data: Optional[str],
    timeout: Optional[int],
) -> None:
    from cycode.cli.exceptions.custom_exceptions import RequestHttpError
    from cycode.cli.utils.get_api_client import get_raw_api_client

    method = method.lower()
    url_path = _validate_path(path)
    params = _parse_query(query)
    headers = _parse_headers(header)

    body = None
    if data is not None:
        if method not in _METHODS_WITH_BODY:
            raise click.ClickException(f'--data is not supported for the {method} method.')
        body = _read_body(data)

    ctx = click.get_current_context()
    client = get_raw_api_client(ctx.find_root())

    kwargs: dict[str, Any] = {'headers': headers or None, 'params': params or None}
    if timeout is not None:
        kwargs['timeout'] = timeout

    logger.debug('Sending raw API request, %s', {'method': method, 'path': url_path})

    try:
        if method == 'get':
            response = client.get(url_path, **kwargs)
        elif method == 'post':
            response = client.post(url_path, body=body, **kwargs)
        else:
            response = client.put(url_path, body=body, **kwargs)
    except RequestHttpError as e:
        click.echo(f'HTTP {e.status_code}: {e.error_message}', err=True)
        raise click.exceptions.Exit(1) from e
    except Exception as e:
        click.echo(f'Error: {e}', err=True)
        raise click.exceptions.Exit(1) from e

    _echo_response_body(response)


def build_raw_api_command() -> click.Command:
    """Build the `cycode platform api` raw request command."""
    return click.Command(
        name='api',
        callback=_callback,
        help=_HELP,
        short_help='[BETA] Send a raw authenticated request to the Cycode API.',
        params=[
            click.Argument(['method'], type=click.Choice(_SUPPORTED_METHODS, case_sensitive=False), required=True),
            click.Argument(['path'], type=click.STRING, required=True),
            click.Option(
                ['-q', '--query'],
                multiple=True,
                metavar='KEY=VALUE',
                help='Query parameter. Repeatable; repeating a key sends multiple values.',
            ),
            click.Option(
                ['-H', '--header'],
                multiple=True,
                metavar='"KEY: VALUE"',
                help='Additional request header. Repeatable. Authorization is managed by the CLI.',
            ),
            click.Option(
                ['-d', '--data'],
                metavar='JSON',
                help='JSON request body for post/put. Use @file to read a file, or - to read stdin.',
            ),
            click.Option(
                ['--timeout'],
                type=click.INT,
                help='Request timeout in seconds. Defaults to the CLI request timeout.',
            ),
        ],
    )
