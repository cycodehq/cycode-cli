"""OpenAPI spec manager: fetch, cache, and parse the Cycode API v4 spec."""

import json
import os
import time
from pathlib import Path
from typing import Optional

from cycode.cli.consts import CYCODE_CONFIGURATION_DIRECTORY
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cyclient import config as cyclient_config
from cycode.logger import get_logger

logger = get_logger('OpenAPI Spec')

_CACHE_DIR = Path.home() / CYCODE_CONFIGURATION_DIRECTORY
_CACHE_FILE = _CACHE_DIR / 'openapi-spec.json'
_CACHE_TTL_SECONDS = int(os.getenv('CYCODE_SPEC_CACHE_TTL', str(24 * 60 * 60)))  # 24h default

_OPENAPI_SPEC_PATH = '/v4/api-docs/cycode-api-swagger.json'


def get_openapi_spec(client_id: Optional[str] = None, client_secret: Optional[str] = None) -> dict:
    """Get the OpenAPI spec, using cache if fresh, otherwise fetching from API.

    The spec is only fetched when the user actually invokes `cycode platform ...`.
    Fetch uses the HTTP client's default timeout; on a slow connection the first
    invocation will block accordingly. Once cached, subsequent invocations within
    the TTL are near-instant.

    Args:
        client_id: Optional client ID override (from CLI flags).
        client_secret: Optional client secret override (from CLI flags).

    Returns:
        Parsed OpenAPI specification dictionary.

    Raises:
        OpenAPISpecError: If spec cannot be loaded from cache or API.
    """
    cached = _load_cached_spec()
    if cached is not None:
        return cached

    return _fetch_and_cache_spec(client_id, client_secret)


def _load_cached_spec() -> Optional[dict]:
    """Load spec from local cache if it exists and is fresh."""
    if not _CACHE_FILE.exists():
        return None

    try:
        mtime = _CACHE_FILE.stat().st_mtime
        if time.time() - mtime > _CACHE_TTL_SECONDS:
            logger.debug('Cached OpenAPI spec is stale (age > %ds)', _CACHE_TTL_SECONDS)
            return None

        spec = json.loads(_CACHE_FILE.read_text(encoding='utf-8'))
        logger.debug('Using cached OpenAPI spec from %s', _CACHE_FILE)
        return spec
    except Exception as e:
        logger.warning('Failed to load cached OpenAPI spec: %s', e)
        return None


def resolve_credentials(client_id: Optional[str] = None, client_secret: Optional[str] = None) -> tuple[str, str]:
    """Resolve credentials from args or the CLI's standard credential chain."""
    if not client_id or not client_secret:
        credentials_manager = CredentialsManager()
        cred_id, cred_secret = credentials_manager.get_credentials()
        client_id = client_id or cred_id
        client_secret = client_secret or cred_secret

    if not client_id or not client_secret:
        raise OpenAPISpecError(
            'Cycode credentials not found. Run `cycode auth` first, '
            'or set CYCODE_CLIENT_ID and CYCODE_CLIENT_SECRET environment variables.'
        )

    return client_id, client_secret


def _fetch_and_cache_spec(client_id: Optional[str] = None, client_secret: Optional[str] = None) -> dict:
    """Fetch OpenAPI spec from API and cache to disk.

    Uses CycodeTokenBasedClient for auth and retries. The spec is served from the app URL,
    so we create a client with app_url as base instead of the default api_url.
    """
    from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient

    cid, csecret = resolve_credentials(client_id, client_secret)

    # The spec is served from app.cycode.com, but token refresh POSTs to api.cycode.com.
    # Ensure the token is fresh BEFORE overriding the base URL so that refresh
    # targets the correct host.
    client = CycodeTokenBasedClient(cid, csecret)
    client.get_access_token()
    client.api_url = cyclient_config.cycode_app_url

    spec_path = _OPENAPI_SPEC_PATH.lstrip('/')
    logger.info('Fetching OpenAPI spec from %s/%s', cyclient_config.cycode_app_url, spec_path)

    try:
        response = client.get(spec_path)
        spec = response.json()
    except Exception as e:
        raise OpenAPISpecError(
            f'Failed to fetch OpenAPI spec. Check your authentication and network connectivity. Error: {e}'
        ) from e

    if not isinstance(spec, dict) or 'paths' not in spec:
        raise OpenAPISpecError('Response does not look like a valid OpenAPI spec (missing "paths" key).')

    # Override server URL with API URL (supports on-premise installations)
    spec['servers'] = [{'url': cyclient_config.cycode_api_url}]

    # Cache to disk
    _cache_spec(spec)

    return spec


def _cache_spec(spec: dict) -> None:
    """Write spec to local cache file atomically (write to temp file, then rename)."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp_file = _CACHE_FILE.with_suffix('.json.tmp')
        tmp_file.write_text(json.dumps(spec), encoding='utf-8')
        tmp_file.replace(_CACHE_FILE)  # atomic on POSIX and Windows
        logger.debug('Cached OpenAPI spec to %s', _CACHE_FILE)
    except Exception as e:
        logger.warning('Failed to cache OpenAPI spec: %s', e)


def parse_spec_commands(spec: dict) -> dict[str, list[dict]]:
    """Parse OpenAPI spec into resource groups with their endpoints.

    Groups endpoints by their first tag, returning a dict of:
    {tag_name: [endpoint_info, ...]}

    Each endpoint_info contains:
    - path: API path (e.g., '/v4/projects/{projectId}')
    - method: HTTP method (e.g., 'get')
    - summary: Human-readable summary
    - description: Detailed description
    - operation_id: Unique operation ID
    - path_params: List of path parameter definitions
    - query_params: List of query parameter definitions
    """
    groups: dict[str, list[dict]] = {}

    for path, methods in spec.get('paths', {}).items():
        for method, details in methods.items():
            tags = details.get('tags', ['other'])
            tag = tags[0] if tags else 'other'

            # Separate path and query parameters
            parameters = details.get('parameters', [])
            path_params = [p for p in parameters if p.get('in') == 'path']
            query_params = [p for p in parameters if p.get('in') == 'query']

            endpoint_info = {
                'path': path,
                'method': method,
                'summary': details.get('summary', ''),
                'description': details.get('description', ''),
                'operation_id': details.get('operationId', ''),
                'path_params': path_params,
                'query_params': query_params,
                'deprecated': details.get('deprecated', False),
            }

            if tag not in groups:
                groups[tag] = []
            groups[tag].append(endpoint_info)

    return groups


class OpenAPISpecError(Exception):
    """Raised when the OpenAPI spec cannot be loaded."""
