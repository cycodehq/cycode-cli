"""OpenAPI-to-Typer translator: dynamically builds CLI commands from the Cycode API v4 spec."""

import json
import re
from typing import Any, Optional

import click

from cycode.cli.apps.api.openapi_spec import OpenAPISpecError, get_openapi_spec, parse_spec_commands
from cycode.logger import get_logger

logger = get_logger('API Command')

# Map OpenAPI parameter types to Click types
_CLICK_TYPE_MAP: dict[str, click.ParamType] = {
    'string': click.STRING,
    'integer': click.INT,
    'number': click.FLOAT,
    'boolean': click.BOOL,
}


def _normalize_tag(tag: str) -> str:
    """Normalize an OpenAPI tag to a CLI-friendly command name.

    'Scan Statistics' -> 'scan-statistics'
    'CLI scan statistics' -> 'cli-scan-statistics'
    """
    return re.sub(r'[^a-z0-9]+', '-', tag.lower()).strip('-')


def _find_common_prefix(paths: list[str]) -> str:
    """Find the longest common path prefix shared by all paths."""
    if not paths:
        return ''
    if len(paths) == 1:
        # For single-path tags, use the parent directory as prefix
        return '/'.join(paths[0].split('/')[:-1])

    common = paths[0]
    for p in paths[1:]:
        while not p.startswith(common + '/') and common != p:
            common = '/'.join(common.split('/')[:-1])
    return common


def _path_to_command_name(path: str, common_prefix: str, has_path_params: bool) -> str:
    """Derive a CLI command name from an API path relative to the tag's common prefix.

    Rules:
    1. Strip the common prefix shared by all endpoints in the tag
    2. Remove path parameter segments ({id})
    3. If nothing remains: 'list' (no path params) or 'view' (has path params)
    4. Otherwise: use remaining segments joined with hyphens

    Examples:
        /v4/projects          (prefix=/v4/projects)  -> list
        /v4/projects/{id}     (prefix=/v4/projects)  -> view
        /v4/projects/assets   (prefix=/v4/projects)  -> assets
        /v4/violations/count  (prefix=/v4/violations) -> count
    """
    # Strip common prefix
    relative = path[len(common_prefix) :] if path.startswith(common_prefix) else path
    relative = relative.strip('/')

    # Remove path parameter segments and empty parts
    parts = [p for p in relative.split('/') if p and not p.startswith('{')]

    if not parts:
        return 'view' if has_path_params else 'list'

    # Join remaining segments with hyphens, normalize to kebab-case
    return re.sub(r'[^a-z0-9]+', '-', '-'.join(parts).lower()).strip('-')


def _param_to_option_name(name: str) -> str:
    """Convert an OpenAPI parameter name to a CLI option name.

    'page_size' -> '--page-size'
    'pageSize' -> '--page-size'
    'filter.status' -> '--filter-status'
    """
    s = re.sub(r'([a-z])([A-Z])', r'\1-\2', name)
    # Replace any non-alphanumeric characters with hyphens
    s = re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')
    return f'--{s}'


def _make_api_request(
    endpoint_path: str,
    method: str,
    path_params: dict[str, str],
    query_params: dict[str, Any],
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> dict:
    """Execute an API request using the CLI's standard auth client."""
    from urllib.parse import quote

    from cycode.cli.apps.api.openapi_spec import resolve_credentials
    from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient

    cid, csecret = resolve_credentials(client_id, client_secret)
    client = CycodeTokenBasedClient(cid, csecret)

    # Substitute path parameters (URL-encoded to prevent path traversal)
    url_path = endpoint_path
    for param_name, param_value in path_params.items():
        url_path = url_path.replace(f'{{{param_name}}}', quote(str(param_value), safe=''))

    filtered_query = {k: v for k, v in query_params.items() if v is not None}

    response = client.get(url_path.lstrip('/'), params=filtered_query)
    return response.json()


def build_api_command_groups(
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> list[tuple[click.Group, str]]:
    """Build Click command groups from the OpenAPI spec.

    Returns a list of (click_group, command_name) tuples.
    """
    try:
        spec = get_openapi_spec(client_id, client_secret)
    except OpenAPISpecError as e:
        logger.warning('Could not load OpenAPI spec: %s', e)
        return []

    groups = parse_spec_commands(spec)
    result = []

    for tag, endpoints in groups.items():
        tag_name = _normalize_tag(tag)

        group = click.Group(name=tag_name, help=f'[BETA] {tag}')

        # Compute common prefix from all GET (non-deprecated) endpoint paths in this tag
        get_endpoints = [ep for ep in endpoints if ep['method'] == 'get' and not ep.get('deprecated')]
        if not get_endpoints:
            continue

        clean_paths = [re.sub(r'/\{[^}]+\}', '', ep['path']) for ep in get_endpoints]
        common_prefix = _find_common_prefix(clean_paths)

        used_names: dict[str, int] = {}

        for endpoint in get_endpoints:
            has_path_params = bool(endpoint['path_params'])
            cmd_name = _path_to_command_name(endpoint['path'], common_prefix, has_path_params)

            # Fix redundancy: if command name matches the tag name, use list/view
            # e.g. "cycode groups groups" -> "cycode groups list"
            if cmd_name == tag_name:
                cmd_name = 'view' if has_path_params else 'list'

            # Handle duplicate names (e.g. deprecated + new endpoint for same resource)
            if cmd_name in used_names:
                used_names[cmd_name] += 1
                cmd_name = f'{cmd_name}-v{used_names[cmd_name]}'
            else:
                used_names[cmd_name] = 1

            cmd = _build_endpoint_command(cmd_name, endpoint)
            group.add_command(cmd, cmd_name)

        result.append((group, tag_name))

    return result


def _build_click_params(endpoint: dict) -> list[click.Parameter]:
    """Build Click parameters from OpenAPI endpoint definition."""
    params: list[click.Parameter] = []

    # Path parameters -> required arguments
    for p in endpoint['path_params']:
        param_type = _CLICK_TYPE_MAP.get(p.get('schema', {}).get('type', 'string'), click.STRING)
        params.append(
            click.Argument(
                [p['name'].replace('-', '_')],
                type=param_type,
                required=True,
            )
        )

    # Query parameters -> --option flags
    for p in endpoint['query_params']:
        param_type = _CLICK_TYPE_MAP.get(p.get('schema', {}).get('type', 'string'), click.STRING)
        option_name = _param_to_option_name(p['name'])
        required = p.get('required', False)
        default = p.get('schema', {}).get('default')

        schema = p.get('schema', {})
        if 'enum' in schema:
            param_type = click.Choice(schema['enum'])

        params.append(
            click.Option(
                [option_name],
                type=param_type,
                required=required,
                default=default,
                help=p.get('description', ''),
                show_default=default is not None,
            )
        )

    return params


def _build_endpoint_command(cmd_name: str, endpoint: dict) -> click.Command:
    """Build a Click command for an API endpoint.

    Path parameters become required CLI arguments.
    Query parameters become --option flags with proper types.
    """
    ep_path = endpoint['path']
    ep_method = endpoint['method']
    ep_path_params = list(endpoint['path_params'])
    ep_query_params = list(endpoint['query_params'])
    ep_description = endpoint['description'] or endpoint['summary']

    # Build a mapping from Click's normalized kwarg name to original OpenAPI param name
    _path_param_map = {p['name'].replace('-', '_').lower(): p['name'] for p in ep_path_params}
    _query_param_map = {re.sub(r'[^a-z0-9]+', '_', p['name'].lower()).strip('_'): p['name'] for p in ep_query_params}

    def _callback(**kwargs: Any) -> None:
        ctx = click.get_current_context()

        # Extract path param values using the mapping
        path_values = {}
        for kwarg_key, original_name in _path_param_map.items():
            if kwarg_key in kwargs and kwargs[kwarg_key] is not None:
                path_values[original_name] = kwargs[kwarg_key]

        # Extract query param values (skip None)
        query_values = {}
        for kwarg_key, original_name in _query_param_map.items():
            value = kwargs.get(kwarg_key)
            if value is not None:
                query_values[original_name] = value

        # Get auth from root context (set by app_callback)
        root_ctx = ctx.find_root()
        client_id = root_ctx.obj.get('client_id') if root_ctx.obj else None
        client_secret = root_ctx.obj.get('client_secret') if root_ctx.obj else None

        try:
            result = _make_api_request(
                ep_path,
                ep_method,
                path_values,
                query_values,
                client_id=client_id,
                client_secret=client_secret,
            )
        except Exception as e:
            click.echo(f'Error: {e}', err=True)
            raise click.Abort from e

        click.echo(json.dumps(result, indent=2))

    return click.Command(
        name=cmd_name,
        callback=_callback,
        help=ep_description,
        short_help=endpoint['summary'],
        params=_build_click_params(endpoint),
    )
