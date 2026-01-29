"""
Scan command for AI guardrails.

This command handles AI IDE hooks by reading JSON from stdin and outputting
a JSON response to stdout. It scans prompts, file reads, and MCP tool calls
for secrets before they are sent to AI models.

Supports multiple IDEs with different hook event types. The specific hook events
supported depend on the IDE being used (e.g., Cursor supports beforeSubmitPrompt,
beforeReadFile, beforeMCPExecution).
"""

import sys
from typing import Annotated

import click
import typer

from cycode.cli.apps.ai_guardrails.scan.handlers import get_handler_for_event
from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.policy import load_policy
from cycode.cli.apps.ai_guardrails.scan.response_builders import get_response_builder
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType
from cycode.cli.apps.ai_guardrails.scan.utils import output_json, safe_json_parse
from cycode.cli.exceptions.custom_exceptions import HttpUnauthorizedError
from cycode.cli.utils.get_api_client import get_ai_security_manager_client, get_scan_cycode_client
from cycode.cli.utils.sentry import add_breadcrumb
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')


def _get_auth_error_message(error: Exception) -> str:
    """Get user-friendly message for authentication errors."""
    if isinstance(error, click.ClickException):
        # Missing credentials
        return f'{error.message} Please run `cycode configure` to set up your credentials.'

    if isinstance(error, HttpUnauthorizedError):
        # Invalid/expired credentials
        return (
            'Unable to authenticate to Cycode. Your credentials are invalid or have expired. '
            'Please run `cycode configure` to update your credentials.'
        )

    # Fallback
    return 'Authentication failed. Please run `cycode configure` to set up your credentials.'


def _initialize_clients(ctx: typer.Context) -> None:
    """Initialize API clients.

    May raise click.ClickException if credentials are missing,
    or HttpUnauthorizedError if credentials are invalid.
    """
    scan_client = get_scan_cycode_client(ctx)
    ctx.obj['client'] = scan_client

    ai_security_client = get_ai_security_manager_client(ctx)
    ctx.obj['ai_security_client'] = ai_security_client


def scan_command(
    ctx: typer.Context,
    ide: Annotated[
        str,
        typer.Option(
            '--ide',
            help='IDE that sent the payload (e.g., "cursor"). Defaults to cursor.',
            hidden=True,
        ),
    ] = 'cursor',
) -> None:
    """Scan content from AI IDE hooks for secrets.

    This command reads a JSON payload from stdin containing hook event data
    and outputs a JSON response to stdout indicating whether to allow or block the action.

    The hook event type is determined from the event field in the payload (field name
    varies by IDE). Each IDE may support different hook events for scanning prompts,
    file access, and tool executions.

    Example usage (from IDE hooks configuration):
        { "command": "cycode ai-guardrails scan" }
    """
    add_breadcrumb('ai-guardrails-scan')

    stdin_data = sys.stdin.read().strip()
    payload = safe_json_parse(stdin_data)

    tool = ide.lower()
    response_builder = get_response_builder(tool)

    if not payload:
        logger.debug('Empty or invalid JSON payload received')
        output_json(response_builder.allow_prompt())
        return

    unified_payload = AIHookPayload.from_payload(payload, tool=tool)
    event_name = unified_payload.event_name
    logger.debug('Processing AI guardrails hook', extra={'event_name': event_name, 'tool': tool})

    workspace_roots = payload.get('workspace_roots', ['.'])
    policy = load_policy(workspace_roots[0])

    try:
        _initialize_clients(ctx)

        handler = get_handler_for_event(event_name)
        if handler is None:
            logger.debug('Unknown hook event, allowing by default', extra={'event_name': event_name})
            output_json(response_builder.allow_prompt())
            return

        response = handler(ctx, unified_payload, policy)
        logger.debug('Hook handler completed', extra={'event_name': event_name, 'response': response})
        output_json(response)

    except (click.ClickException, HttpUnauthorizedError) as e:
        error_message = _get_auth_error_message(e)
        if event_name == AiHookEventType.PROMPT:
            output_json(response_builder.deny_prompt(error_message))
            return
        output_json(response_builder.deny_permission(error_message, 'Authentication required'))

    except Exception as e:
        logger.error('Hook handler failed', exc_info=e)
        if policy.get('fail_open', True):
            output_json(response_builder.allow_prompt())
            return
        if event_name == AiHookEventType.PROMPT:
            output_json(response_builder.deny_prompt('Cycode guardrails error - blocking due to fail-closed policy'))
            return
        output_json(response_builder.deny_permission('Cycode guardrails error', 'Blocking due to fail-closed policy'))
