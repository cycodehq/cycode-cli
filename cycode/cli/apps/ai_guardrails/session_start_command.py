"""Handle AI guardrails session start: auth, conversation creation, session context."""

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Optional

import typer

from cycode.cli.apps.ai_guardrails.ides import DEFAULT_IDE_NAME, collect_all_session_contexts, get_ide
from cycode.cli.apps.ai_guardrails.scan.utils import read_stdin_text, safe_json_parse
from cycode.cli.apps.auth.auth_common import get_authorization_info
from cycode.cli.apps.auth.auth_manager import AuthManager
from cycode.cli.exceptions.handle_auth_errors import handle_auth_exception
from cycode.cli.utils.get_api_client import get_ai_security_manager_client
from cycode.cli.utils.host_info import (
    get_hostname,
    get_last_login_user,
    get_os_version,
    get_platform_name,
    get_serial_number,
)
from cycode.logger import get_logger

if TYPE_CHECKING:
    from cycode.cyclient.ai_security_manager_client import AISecurityManagerClient

logger = get_logger('AI Guardrails')

_SESSION_CONTEXT_CACHE_FILE = '.session-context-cache'
_SESSION_CONTEXT_TTL_SECONDS = 7 * 24 * 60 * 60


def _session_context_cache_path() -> Path:
    return Path.home() / '.cycode' / _SESSION_CONTEXT_CACHE_FILE


def _session_context_digest(report: dict) -> str:
    """Deterministic hash of the outgoing payload (not the raw config files, which churn)."""
    canonical = json.dumps(report, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _should_skip_report(digest: str, tenant_id: Optional[str]) -> bool:
    """Skip when the same payload was already sent for this tenant and the TTL hasn't expired."""
    try:
        cache = json.loads(_session_context_cache_path().read_text(encoding='utf-8'))
        return (
            cache.get('hash') == digest
            and cache.get('tenant_id') == tenant_id
            and time.time() - float(cache.get('sent_at', 0)) < _SESSION_CONTEXT_TTL_SECONDS
        )
    except Exception:
        # Missing/corrupt cache reads as a miss - over-sending is harmless
        return False


def _save_report_cache(digest: str, tenant_id: Optional[str]) -> None:
    try:
        cache_path = _session_context_cache_path()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(
            json.dumps({'hash': digest, 'tenant_id': tenant_id, 'sent_at': time.time()}), encoding='utf-8'
        )
    except Exception as e:
        logger.debug('Failed to write session context cache', exc_info=e)


def _report_session_context(
    ai_client: 'AISecurityManagerClient',
    user_email: Optional[str],
    tenant_id: Optional[str],
) -> None:
    """Report the device + cross-IDE session context to the AI security manager. Never raises.

    The device context is always reported. MCP configs are collected from every registered IDE,
    not just the triggering one. Unchanged payloads are skipped via a hash cache until the TTL expires.
    """
    try:
        config_files_by_ide, enabled_plugins = collect_all_session_contexts()
        report = {
            'hostname': get_hostname(),
            'platform_name': get_platform_name(),
            'os_version': get_os_version(),
            'serial_number': get_serial_number(),
            'last_login_user': get_last_login_user(),
            # Sorted by path so the digest is stable regardless of IDE registry order.
            'config_files': sorted(config_files_by_ide.values(), key=lambda f: f['path']),
            'enabled_plugins': enabled_plugins,
            'user_email': user_email,
        }

        digest = _session_context_digest(report)
        if _should_skip_report(digest, tenant_id):
            logger.debug('Session context unchanged; skipping report')
            return

        if ai_client.report_session_context(**report):
            _save_report_cache(digest, tenant_id)
    except Exception as e:
        logger.debug('Failed to report session context', exc_info=e)


def session_start_command(
    ctx: typer.Context,
    ide: Annotated[
        str,
        typer.Option(
            '--ide',
            help='IDE that triggered the session start.',
            hidden=True,
        ),
    ] = DEFAULT_IDE_NAME,
) -> None:
    """Handle session start: ensure auth, create conversation, report session context."""
    ide_integration = get_ide(ide)

    # Ensure authentication
    auth_info = get_authorization_info(ctx)
    if auth_info is None:
        logger.debug('Not authenticated, starting authentication')
        try:
            AuthManager().authenticate()
        except Exception as err:
            handle_auth_exception(ctx, err)
            return
        auth_info = get_authorization_info(ctx)
    else:
        logger.debug('Already authenticated')

    # Read stdin payload (backward compat: old hooks pipe no stdin)
    if sys.stdin.isatty():
        logger.debug('No stdin payload (TTY), skipping session initialization')
        return

    stdin_data = read_stdin_text().strip()
    payload = safe_json_parse(stdin_data)
    if not payload:
        logger.debug('Empty or invalid stdin payload, skipping session initialization')
        return

    # Build session payload + initialize API client
    session_payload = ide_integration.build_session_payload(payload)

    try:
        ai_client = get_ai_security_manager_client(ctx)
    except Exception as e:
        logger.debug('Failed to initialize AI security client', exc_info=e)
        return

    # Create conversation
    try:
        ai_client.create_conversation(session_payload)
    except Exception as e:
        logger.debug('Failed to create conversation during session start', exc_info=e)

    # Report session context (device + cross-IDE MCP servers and plugins)
    _report_session_context(ai_client, session_payload.ide_user_email, auth_info.tenant_id)
