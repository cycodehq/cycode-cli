"""
Prompt scan command for AI guardrails.

This command handles AI IDE hooks by reading JSON from stdin and outputting
a JSON response to stdout.

Supports multiple IDEs with different hook event types. The specific hook events
supported depend on the IDE being used (e.g., Cursor supports beforeSubmitPrompt,
beforeReadFile, beforeMCPExecution).
"""

import sys
from typing import Annotated

import typer

from cycode.cli.apps.scan.prompt.handlers import get_handler_for_event
from cycode.cli.apps.scan.prompt.payload import AIHookPayload
from cycode.cli.apps.scan.prompt.policy import load_policy
from cycode.cli.apps.scan.prompt.response_builders import get_response_builder
from cycode.cli.apps.scan.prompt.types import AiHookEventType
from cycode.cli.apps.scan.prompt.utils import output_json, safe_json_parse
from cycode.cli.utils.get_api_client import get_ai_security_manager_client
from cycode.cli.utils.sentry import add_breadcrumb
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')


def prompt_command(
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
    """Handle AI guardrails hooks from supported IDEs.

    This command reads a JSON payload from stdin containing hook event data
    and outputs a JSON response to stdout indicating whether to allow or block the action.

    The hook event type is determined from the event field in the payload (field name
    varies by IDE). Each IDE may support different hook events for scanning prompts,
    file access, and tool executions.

    Example usage (from IDE hooks configuration):
        { "command": "cycode scan prompt" }
    """
    add_breadcrumb('prompt')

    # Initialize AI Security Manager client
    ai_security_client = get_ai_security_manager_client(ctx)
    ctx.obj['ai_security_client'] = ai_security_client

    # Read JSON payload from stdin
    stdin_data = sys.stdin.read().strip()
    payload = safe_json_parse(stdin_data)

    tool = ide.lower()

    # Get response builder for this IDE
    response_builder = get_response_builder(tool)

    if not payload:
        logger.debug('Empty or invalid JSON payload received')
        output_json(response_builder.allow_prompt())
        return

    # Create unified payload object
    unified_payload = AIHookPayload.from_payload(payload, tool=tool)

    # Extract event type from unified payload
    event_name = unified_payload.event_name
    logger.debug('Processing AI guardrails hook', extra={'event_name': event_name, 'tool': tool})

    # Load policy (merges defaults <- user config <- repo config)
    # Extract first workspace root from payload if available
    workspace_roots = payload.get('workspace_roots', ['.'])
    policy = load_policy(workspace_roots[0])

    # Get the appropriate handler for this event
    handler = get_handler_for_event(event_name)

    if handler is None:
        logger.debug('Unknown hook event, allowing by default', extra={'event_name': event_name})
        # Unknown event type - allow by default
        output_json(response_builder.allow_prompt())
        return

    # Execute the handler and output the response
    try:
        response = handler(ctx, unified_payload, policy)
        logger.debug('Hook handler completed', extra={'event_name': event_name, 'response': response})
        output_json(response)
    except Exception as e:
        logger.error('Hook handler failed', exc_info=e)
        # Fail open by default
        if policy.get('fail_open', True):
            output_json(response_builder.allow_prompt())
        else:
            # Fail closed
            if event_name == AiHookEventType.PROMPT:
                output_json(
                    response_builder.deny_prompt('Cycode guardrails error - blocking due to fail-closed policy')
                )
            else:
                output_json(
                    response_builder.deny_permission('Cycode guardrails error', 'Blocking due to fail-closed policy')
                )
