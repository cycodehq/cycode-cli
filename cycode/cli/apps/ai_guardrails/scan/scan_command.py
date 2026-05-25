"""Scan command for AI guardrails IDE hooks.

Reads a JSON payload from stdin, routes it through the IDE-specific parser and
the shared event handlers, then writes an IDE-specific JSON response to stdout.

The handlers in ``handlers.py`` are agent-agnostic (they return
``HookDecision``); ``IDE.build_hook_response`` is the per-IDE translation step.
"""

import sys
from typing import Annotated, Optional, Union

import click
import typer

from cycode.cli.apps.ai_guardrails.ides import DEFAULT_IDE_NAME, get_ide
from cycode.cli.apps.ai_guardrails.ides.base import HookDecision
from cycode.cli.apps.ai_guardrails.scan.handlers import get_handler_for_event
from cycode.cli.apps.ai_guardrails.scan.policy import load_policy
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType
from cycode.cli.apps.ai_guardrails.scan.utils import output_json, safe_json_parse
from cycode.cli.exceptions.custom_exceptions import HttpUnauthorizedError
from cycode.cli.utils.get_api_client import get_ai_security_manager_client, get_scan_cycode_client
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')


def _get_auth_error_message(error: Exception) -> str:
    """User-friendly message for authentication errors."""
    if isinstance(error, click.ClickException):
        # Missing credentials
        return f'{error.message} Please run `cycode auth` to set up your credentials.'

    if isinstance(error, HttpUnauthorizedError):
        # Invalid/expired credentials
        return (
            'Unable to authenticate to Cycode. Your credentials are invalid or have expired. '
            'Please run `cycode auth` to update your credentials.'
        )

    # Fallback
    return 'Authentication failed. Please run `cycode auth` to set up your credentials.'


def _deny_for_event(
    event_name: Optional[Union[str, AiHookEventType]],
    user_message: str,
    agent_message: Optional[str] = None,
) -> HookDecision:
    """Build a deny decision matched to ``event_name``'s response shape.

    PROMPT events use the prompt-block shape (no agent_message). For anything
    else — including unknown event names — fall back to FILE_READ since
    FILE_READ and MCP_EXECUTION share the same response shape on both IDEs.
    """
    if event_name == AiHookEventType.PROMPT:
        return HookDecision.deny(AiHookEventType.PROMPT, user_message)
    target = event_name if isinstance(event_name, AiHookEventType) else AiHookEventType.FILE_READ
    return HookDecision.deny(target, user_message, agent_message)


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
    ] = DEFAULT_IDE_NAME,
) -> None:
    """Scan content from AI IDE hooks for secrets.

    Reads a JSON payload from stdin and outputs a JSON response to stdout
    indicating whether to allow or block the action.
    """
    ide_integration = get_ide(ide)

    stdin_data = sys.stdin.read().strip()
    payload = safe_json_parse(stdin_data)

    if not payload:
        logger.debug('Empty or invalid JSON payload received')
        output_json(ide_integration.build_hook_response(HookDecision.allow(AiHookEventType.PROMPT)))
        return

    # Prevent cross-IDE processing (e.g. Cursor reading Claude Code hooks
    # from ~/.claude/settings.json).
    if not ide_integration.matches_payload(payload):
        logger.debug(
            'Payload event does not match expected IDE, skipping',
            extra={'hook_event_name': payload.get('hook_event_name'), 'expected_ide': ide_integration.name},
        )
        output_json(ide_integration.build_hook_response(HookDecision.allow(AiHookEventType.PROMPT)))
        return

    unified_payload = ide_integration.parse_hook_payload(payload)
    event_name = unified_payload.event_name
    logger.debug('Processing AI guardrails hook', extra={'event_name': event_name, 'ide': ide_integration.name})

    workspace_roots = payload.get('workspace_roots', ['.'])
    policy = load_policy(workspace_roots[0])

    try:
        _initialize_clients(ctx)

        handler = get_handler_for_event(event_name)
        if handler is None:
            logger.debug('Unknown hook event, allowing by default', extra={'event_name': event_name})
            output_json(ide_integration.build_hook_response(HookDecision.allow(AiHookEventType.PROMPT)))
            return

        decision = handler(ctx, unified_payload, policy)
        logger.debug('Hook handler completed', extra={'event_name': event_name, 'action': decision.action.value})
        output_json(ide_integration.build_hook_response(decision))

    except (click.ClickException, HttpUnauthorizedError) as e:
        output_json(
            ide_integration.build_hook_response(
                _deny_for_event(event_name, _get_auth_error_message(e), 'Authentication required')
            )
        )

    except Exception as e:
        logger.error('Hook handler failed', exc_info=e)
        if policy.get('fail_open', True):
            output_json(ide_integration.build_hook_response(HookDecision.allow(AiHookEventType.PROMPT)))
            return
        output_json(
            ide_integration.build_hook_response(
                _deny_for_event(
                    event_name,
                    'Cycode guardrails error - blocking due to fail-closed policy'
                    if event_name == AiHookEventType.PROMPT
                    else 'Cycode guardrails error',
                    'Blocking due to fail-closed policy',
                )
            )
        )
