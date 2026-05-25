"""Handle AI guardrails session start: auth, conversation creation, session context."""

import sys
from typing import TYPE_CHECKING, Annotated, Optional

import typer

from cycode.cli.apps.ai_guardrails.ides import DEFAULT_IDE_NAME, get_ide
from cycode.cli.apps.ai_guardrails.ides.base import IDE
from cycode.cli.apps.ai_guardrails.scan.utils import safe_json_parse
from cycode.cli.apps.auth.auth_common import get_authorization_info
from cycode.cli.apps.auth.auth_manager import AuthManager
from cycode.cli.exceptions.handle_auth_errors import handle_auth_exception
from cycode.cli.utils.get_api_client import get_ai_security_manager_client
from cycode.logger import get_logger

if TYPE_CHECKING:
    from cycode.cyclient.ai_security_manager_client import AISecurityManagerClient

logger = get_logger('AI Guardrails')


def _report_session_context(ai_client: 'AISecurityManagerClient', ide: IDE, user_email: Optional[str]) -> None:
    """Report IDE session context to the AI security manager. Never raises."""
    try:
        mcp_servers, enabled_plugins = ide.get_session_context()
        if not mcp_servers and not enabled_plugins:
            return
        ai_client.report_session_context(
            mcp_servers=mcp_servers,
            enabled_plugins=enabled_plugins,
            user_email=user_email,
        )
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

    # Step 1: Ensure authentication
    auth_info = get_authorization_info(ctx)
    if auth_info is None:
        logger.debug('Not authenticated, starting authentication')
        try:
            AuthManager().authenticate()
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

    # Step 3: Build session payload + initialize API client
    session_payload = ide_integration.build_session_payload(payload)

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

    # Step 5: Report session context (MCP servers, enabled plugins)
    _report_session_context(ai_client, ide_integration, session_payload.ide_user_email)
