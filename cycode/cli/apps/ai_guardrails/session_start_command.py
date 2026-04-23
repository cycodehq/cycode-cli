import sys
from typing import TYPE_CHECKING, Annotated

import typer

from cycode.cli.apps.ai_guardrails.consts import AIIDEType
from cycode.cli.apps.ai_guardrails.scan.claude_config import (
    get_mcp_servers,
    get_user_email,
    load_claude_config,
    load_claude_settings,
    resolve_plugins,
)
from cycode.cli.apps.ai_guardrails.scan.cursor_config import load_cursor_config
from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload, extract_from_claude_transcript
from cycode.cli.apps.ai_guardrails.scan.utils import safe_json_parse
from cycode.cli.apps.auth.auth_common import get_authorization_info
from cycode.cli.apps.auth.auth_manager import AuthManager
from cycode.cli.exceptions.handle_auth_errors import handle_auth_exception
from cycode.cli.utils.get_api_client import get_ai_security_manager_client
from cycode.logger import get_logger

if TYPE_CHECKING:
    from cycode.cyclient.ai_security_manager_client import AISecurityManagerClient

logger = get_logger('AI Guardrails')


def _build_session_payload(payload: dict, ide: str) -> AIHookPayload:
    """Build an AIHookPayload from a session-start stdin payload."""
    if ide == AIIDEType.CLAUDE_CODE:
        claude_config = load_claude_config()
        ide_user_email = get_user_email(claude_config) if claude_config else None
        ide_version, _, _ = extract_from_claude_transcript(payload.get('transcript_path'))

        return AIHookPayload(
            conversation_id=payload.get('session_id'),
            ide_user_email=ide_user_email,
            model=payload.get('model'),
            ide_provider=AIIDEType.CLAUDE_CODE.value,
            ide_version=ide_version,
            source=payload.get('source'),
        )

    if ide == AIIDEType.CODEX:
        return AIHookPayload(
            conversation_id=payload.get('session_id'),
            generation_id=payload.get('turn_id'),
            model=payload.get('model'),
            ide_provider=AIIDEType.CODEX.value,
            ide_version=payload.get('codex_version'),
        )

    # Cursor
    return AIHookPayload(
        conversation_id=payload.get('conversation_id'),
        ide_user_email=payload.get('user_email'),
        model=payload.get('model'),
        ide_provider=AIIDEType.CURSOR.value,
        ide_version=payload.get('cursor_version'),
    )


def _get_claude_code_session_context() -> tuple[dict, dict]:
    """Return (mcp_servers, enabled_plugins) for Claude Code.

    Merges MCP servers from ~/.claude.json (user-configured) with those contributed
    by enabled plugins. Plugin metadata (name, version, description) is included in
    the enabled_plugins dict when resolvable.
    """
    config = load_claude_config()
    mcp_servers = dict(get_mcp_servers(config) or {}) if config else {}

    settings = load_claude_settings()
    if settings:
        plugin_mcp, enriched_plugins = resolve_plugins(settings)
        mcp_servers.update(plugin_mcp)
    else:
        enriched_plugins = {}

    return mcp_servers, enriched_plugins


def _get_cursor_session_context() -> tuple[dict, dict]:
    """Return (mcp_servers, enabled_plugins) for Cursor. Cursor has no plugin system."""
    config = load_cursor_config()
    mcp_servers = dict(get_mcp_servers(config) or {}) if config else {}
    return mcp_servers, {}


def _report_session_context(ai_client: 'AISecurityManagerClient', ide: str) -> None:
    """Report IDE session context to the AI security manager. Never raises."""
    try:
        if ide == AIIDEType.CLAUDE_CODE:
            mcp_servers, enabled_plugins = _get_claude_code_session_context()
        elif ide == AIIDEType.CURSOR:
            mcp_servers, enabled_plugins = _get_cursor_session_context()
        else:
            return

        if not mcp_servers and not enabled_plugins:
            return
        ai_client.report_session_context(mcp_servers=mcp_servers, enabled_plugins=enabled_plugins)
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
    ] = AIIDEType.CURSOR.value,
) -> None:
    """Handle session start: ensure auth, create conversation, report session context."""
    # Step 1: Ensure authentication
    auth_info = get_authorization_info(ctx)
    if auth_info is None:
        logger.debug('Not authenticated, starting authentication')
        try:
            auth_manager = AuthManager()
            auth_manager.authenticate()
        except Exception as err:
            handle_auth_exception(ctx, err)
            return
    else:
        logger.debug('Already authenticated')

    # Step 2: Read stdin payload (backward compat: old hooks pipe no stdin)
    if sys.stdin.isatty():
        logger.debug('No stdin payload (TTY), skipping session initialization')
        return

    stdin_data = sys.stdin.read().strip()
    payload = safe_json_parse(stdin_data)
    if not payload:
        logger.debug('Empty or invalid stdin payload, skipping session initialization')
        return

    # Step 3: Build session payload and initialize API client
    session_payload = _build_session_payload(payload, ide)

    try:
        ai_client = get_ai_security_manager_client(ctx)
    except Exception as e:
        logger.debug('Failed to initialize AI security client', exc_info=e)
        return

    # Step 4: Create conversation
    try:
        ai_client.create_conversation(session_payload)
    except Exception as e:
        logger.debug('Failed to create conversation during session start', exc_info=e)

    # Step 5: Report session context (MCP servers)
    _report_session_context(ai_client, ide)
