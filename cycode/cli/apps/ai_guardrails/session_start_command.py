import sys
from typing import Annotated

import typer

from cycode.cli.apps.ai_guardrails.consts import AIIDEType
from cycode.cli.apps.ai_guardrails.scan.claude_config import get_mcp_servers, get_user_email, load_claude_config
from cycode.cli.apps.ai_guardrails.scan.cursor_config import load_cursor_config
from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload, _extract_from_claude_transcript
from cycode.cli.apps.ai_guardrails.scan.utils import safe_json_parse
from cycode.cli.apps.auth.auth_common import get_authorization_info
from cycode.cli.apps.auth.auth_manager import AuthManager
from cycode.cli.exceptions.handle_auth_errors import handle_auth_exception
from cycode.cli.utils.get_api_client import get_ai_security_manager_client
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')


def _build_session_payload(payload: dict, ide: str) -> AIHookPayload:
    """Build an AIHookPayload from a session-start stdin payload."""
    if ide == AIIDEType.CLAUDE_CODE:
        claude_config = load_claude_config()
        ide_user_email = get_user_email(claude_config) if claude_config else None
        ide_version, _, _ = _extract_from_claude_transcript(payload.get('transcript_path'))

        return AIHookPayload(
            conversation_id=payload.get('session_id'),
            ide_user_email=ide_user_email,
            model=payload.get('model'),
            ide_provider=AIIDEType.CLAUDE_CODE.value,
            ide_version=ide_version,
        )

    # Cursor
    return AIHookPayload(
        conversation_id=payload.get('conversation_id'),
        ide_user_email=payload.get('user_email'),
        model=payload.get('model'),
        ide_provider=AIIDEType.CURSOR.value,
        ide_version=payload.get('cursor_version'),
    )


def _get_mcp_servers_for_ide(ide: str) -> dict:
    """Return configured MCP servers for the given IDE, or empty dict."""
    if ide == AIIDEType.CLAUDE_CODE:
        config = load_claude_config()
    elif ide == AIIDEType.CURSOR:
        config = load_cursor_config()
    else:
        return {}
    return get_mcp_servers(config) or {} if config else {}


def _report_session_context(ai_client, ide: str) -> None:
    """Report IDE MCP servers to the AI security manager. Never raises."""
    mcp_servers = _get_mcp_servers_for_ide(ide)
    if not mcp_servers:
        return
    ai_client.report_session_context(mcp_servers)


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
