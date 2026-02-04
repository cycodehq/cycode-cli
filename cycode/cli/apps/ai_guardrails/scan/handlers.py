"""
Hook handlers for AI IDE events.

Each handler receives a unified payload from an IDE, applies policy rules,
and returns a response that either allows or blocks the action.
"""

import json
import os
from multiprocessing.pool import ThreadPool
from multiprocessing.pool import TimeoutError as PoolTimeoutError
from typing import Callable, Optional

import typer

from cycode.cli.apps.ai_guardrails.consts import PolicyMode
from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.policy import get_policy_value
from cycode.cli.apps.ai_guardrails.scan.response_builders import get_response_builder
from cycode.cli.apps.ai_guardrails.scan.types import AiHookEventType, AIHookOutcome, BlockReason
from cycode.cli.apps.ai_guardrails.scan.utils import is_denied_path, truncate_utf8
from cycode.cli.apps.scan.code_scanner import _get_scan_documents_thread_func
from cycode.cli.apps.scan.scan_parameters import get_scan_parameters
from cycode.cli.cli_types import ScanTypeOption, SeverityOption
from cycode.cli.models import Document
from cycode.cli.utils.progress_bar import DummyProgressBar, ScanProgressBarSection
from cycode.cli.utils.scan_utils import build_violation_summary
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')


def handle_before_submit_prompt(ctx: typer.Context, payload: AIHookPayload, policy: dict) -> dict:
    """
    Handle beforeSubmitPrompt hook.

    Scans prompt text for secrets before it's sent to the AI model.
    Returns {"continue": False} to block, {"continue": True} to allow.
    """
    ai_client = ctx.obj['ai_security_client']
    ide = payload.ide_provider
    response_builder = get_response_builder(ide)

    prompt_config = get_policy_value(policy, 'prompt', default={})
    ai_client.create_conversation(payload)
    if not get_policy_value(prompt_config, 'enabled', default=True):
        ai_client.create_event(payload, AiHookEventType.PROMPT, AIHookOutcome.ALLOWED)
        return response_builder.allow_prompt()

    mode = get_policy_value(policy, 'mode', default=PolicyMode.BLOCK)
    prompt = payload.prompt or ''
    max_bytes = get_policy_value(policy, 'secrets', 'max_bytes', default=200000)
    timeout_ms = get_policy_value(policy, 'secrets', 'timeout_ms', default=30000)
    clipped = truncate_utf8(prompt, max_bytes)

    scan_id = None
    block_reason = None
    outcome = AIHookOutcome.ALLOWED
    error_message = None

    try:
        violation_summary, scan_id = _scan_text_for_secrets(ctx, clipped, timeout_ms)

        if violation_summary:
            block_reason = BlockReason.SECRETS_IN_PROMPT
            action = get_policy_value(prompt_config, 'action', default=PolicyMode.BLOCK)
            if action == PolicyMode.BLOCK and mode == PolicyMode.BLOCK:
                outcome = AIHookOutcome.BLOCKED
                user_message = f'{violation_summary}. Remove secrets before sending.'
                return response_builder.deny_prompt(user_message)
            outcome = AIHookOutcome.WARNED
        return response_builder.allow_prompt()
    except Exception as e:
        outcome = (
            AIHookOutcome.ALLOWED if get_policy_value(policy, 'fail_open', default=True) else AIHookOutcome.BLOCKED
        )
        block_reason = BlockReason.SCAN_FAILURE
        error_message = str(e)
        raise e
    finally:
        ai_client.create_event(
            payload,
            AiHookEventType.PROMPT,
            outcome,
            scan_id=scan_id,
            block_reason=block_reason,
            error_message=error_message,
        )


def handle_before_read_file(ctx: typer.Context, payload: AIHookPayload, policy: dict) -> dict:
    """
    Handle beforeReadFile hook.

    Blocks sensitive files (via deny_globs) and scans file content for secrets.
    Returns {"permission": "deny"} to block, {"permission": "allow"} to allow.
    """
    ai_client = ctx.obj['ai_security_client']
    ide = payload.ide_provider
    response_builder = get_response_builder(ide)

    file_read_config = get_policy_value(policy, 'file_read', default={})
    ai_client.create_conversation(payload)
    if not get_policy_value(file_read_config, 'enabled', default=True):
        ai_client.create_event(payload, AiHookEventType.FILE_READ, AIHookOutcome.ALLOWED)
        return response_builder.allow_permission()

    mode = get_policy_value(policy, 'mode', default=PolicyMode.BLOCK)
    file_path = payload.file_path or ''
    action = get_policy_value(file_read_config, 'action', default=PolicyMode.BLOCK)

    scan_id = None
    block_reason = None
    outcome = AIHookOutcome.ALLOWED
    error_message = None

    try:
        # Check path-based denylist first
        if is_denied_path(file_path, policy):
            block_reason = BlockReason.SENSITIVE_PATH
            if mode == PolicyMode.BLOCK and action == PolicyMode.BLOCK:
                outcome = AIHookOutcome.BLOCKED
                user_message = f'Cycode blocked sending {file_path} to the AI (sensitive path policy).'
                return response_builder.deny_permission(
                    user_message,
                    'This file path is classified as sensitive; do not read/send it to the model.',
                )
            # Warn mode - ask user for permission
            outcome = AIHookOutcome.WARNED
            user_message = f'Cycode flagged {file_path} as sensitive. Allow reading?'
            return response_builder.ask_permission(
                user_message,
                'This file path is classified as sensitive; proceed with caution.',
            )

        # Scan file content if enabled
        if get_policy_value(file_read_config, 'scan_content', default=True):
            violation_summary, scan_id = _scan_path_for_secrets(ctx, file_path, policy)
            if violation_summary:
                block_reason = BlockReason.SECRETS_IN_FILE
                if mode == PolicyMode.BLOCK and action == PolicyMode.BLOCK:
                    outcome = AIHookOutcome.BLOCKED
                    user_message = f'Cycode blocked reading {file_path}. {violation_summary}'
                    return response_builder.deny_permission(
                        user_message,
                        'Secrets detected; do not send this file to the model.',
                    )
                # Warn mode - ask user for permission
                outcome = AIHookOutcome.WARNED
                user_message = f'Cycode detected secrets in {file_path}. {violation_summary}'
                return response_builder.ask_permission(
                    user_message,
                    'Possible secrets detected; proceed with caution.',
                )
            return response_builder.allow_permission()

        return response_builder.allow_permission()
    except Exception as e:
        outcome = (
            AIHookOutcome.ALLOWED if get_policy_value(policy, 'fail_open', default=True) else AIHookOutcome.BLOCKED
        )
        block_reason = BlockReason.SCAN_FAILURE
        error_message = str(e)
        raise e
    finally:
        ai_client.create_event(
            payload,
            AiHookEventType.FILE_READ,
            outcome,
            scan_id=scan_id,
            block_reason=block_reason,
            error_message=error_message,
        )


def handle_before_mcp_execution(ctx: typer.Context, payload: AIHookPayload, policy: dict) -> dict:
    """
    Handle beforeMCPExecution hook.

    Scans tool arguments for secrets before MCP tool execution.
    Returns {"permission": "deny"} to block, {"permission": "ask"} to warn,
    {"permission": "allow"} to allow.
    """
    ai_client = ctx.obj['ai_security_client']
    ide = payload.ide_provider
    response_builder = get_response_builder(ide)

    mcp_config = get_policy_value(policy, 'mcp', default={})
    ai_client.create_conversation(payload)
    if not get_policy_value(mcp_config, 'enabled', default=True):
        ai_client.create_event(payload, AiHookEventType.MCP_EXECUTION, AIHookOutcome.ALLOWED)
        return response_builder.allow_permission()

    mode = get_policy_value(policy, 'mode', default=PolicyMode.BLOCK)
    tool = payload.mcp_tool_name or 'unknown'
    args = payload.mcp_arguments or {}
    args_text = args if isinstance(args, str) else json.dumps(args)
    max_bytes = get_policy_value(policy, 'secrets', 'max_bytes', default=200000)
    timeout_ms = get_policy_value(policy, 'secrets', 'timeout_ms', default=30000)
    clipped = truncate_utf8(args_text, max_bytes)
    action = get_policy_value(mcp_config, 'action', default=PolicyMode.BLOCK)

    scan_id = None
    block_reason = None
    outcome = AIHookOutcome.ALLOWED
    error_message = None

    try:
        if get_policy_value(mcp_config, 'scan_arguments', default=True):
            violation_summary, scan_id = _scan_text_for_secrets(ctx, clipped, timeout_ms)
            if violation_summary:
                block_reason = BlockReason.SECRETS_IN_MCP_ARGS
                if mode == PolicyMode.BLOCK and action == PolicyMode.BLOCK:
                    outcome = AIHookOutcome.BLOCKED
                    user_message = f'Cycode blocked MCP tool call "{tool}". {violation_summary}'
                    return response_builder.deny_permission(
                        user_message,
                        'Do not pass secrets to tools. Use secret references (name/id) instead.',
                    )
                outcome = AIHookOutcome.WARNED
                return response_builder.ask_permission(
                    f'{violation_summary} in MCP tool call "{tool}". Allow execution?',
                    'Possible secrets detected in tool arguments; proceed with caution.',
                )

        return response_builder.allow_permission()
    except Exception as e:
        outcome = (
            AIHookOutcome.ALLOWED if get_policy_value(policy, 'fail_open', default=True) else AIHookOutcome.BLOCKED
        )
        block_reason = BlockReason.SCAN_FAILURE
        error_message = str(e)
        raise e
    finally:
        ai_client.create_event(
            payload,
            AiHookEventType.MCP_EXECUTION,
            outcome,
            scan_id=scan_id,
            block_reason=block_reason,
            error_message=error_message,
        )


def get_handler_for_event(event_type: str) -> Optional[Callable[[typer.Context, AIHookPayload, dict], dict]]:
    """Get the appropriate handler function for a canonical event type.

    Args:
        event_type: Canonical event type string (from AiHookEventType enum)

    Returns:
        Handler function or None if event type is not recognized
    """
    handlers = {
        AiHookEventType.PROMPT.value: handle_before_submit_prompt,
        AiHookEventType.FILE_READ.value: handle_before_read_file,
        AiHookEventType.MCP_EXECUTION.value: handle_before_mcp_execution,
    }
    return handlers.get(event_type)


def _setup_scan_context(ctx: typer.Context) -> typer.Context:
    """Set up minimal context for scan_documents without progress bars or printing."""

    # Set up minimal required context
    ctx.obj['progress_bar'] = DummyProgressBar([ScanProgressBarSection])
    ctx.obj['sync'] = True  # Synchronous scan
    ctx.obj['scan_type'] = ScanTypeOption.SECRET  # AI guardrails always scans for secrets
    ctx.obj['severity_threshold'] = SeverityOption.INFO  # Report all severities

    # Set command name for scan logic
    ctx.info_name = 'ai_guardrails'

    return ctx


def _perform_scan(
    ctx: typer.Context, documents: list[Document], scan_parameters: dict, timeout_seconds: float
) -> tuple[Optional[str], Optional[str]]:
    """
    Perform a scan on documents and extract results.

    Returns tuple of (violation_summary, scan_id) if secrets found, (None, scan_id) if clean.
    Raises exception if scan fails or times out (triggers fail_open policy).
    """
    if not documents:
        return None, None

    # Get the thread function for scanning
    scan_batch_thread_func = _get_scan_documents_thread_func(
        ctx, is_git_diff=False, is_commit_range=False, scan_parameters=scan_parameters
    )

    # Use ThreadPool.apply_async with timeout to abort if scan takes too long
    # This uses the same ThreadPool mechanism as run_parallel_batched_scan but with timeout support
    with ThreadPool(processes=1) as pool:
        result = pool.apply_async(scan_batch_thread_func, (documents,))
        try:
            scan_id, error, local_scan_result = result.get(timeout=timeout_seconds)
        except PoolTimeoutError:
            logger.debug('Scan timed out after %s seconds', timeout_seconds)
            raise RuntimeError(f'Scan timed out after {timeout_seconds} seconds') from None

    # Check if scan failed - raise exception to trigger fail_open policy
    if error:
        raise RuntimeError(error.message)

    if not local_scan_result:
        return None, None

    scan_id = local_scan_result.scan_id

    # Check if there are any detections
    if local_scan_result.detections_count > 0:
        violation_summary = build_violation_summary([local_scan_result])
        return violation_summary, scan_id

    return None, scan_id


def _scan_text_for_secrets(ctx: typer.Context, text: str, timeout_ms: int) -> tuple[Optional[str], Optional[str]]:
    """
    Scan text content for secrets using Cycode CLI.

    Returns tuple of (violation_summary, scan_id) if secrets found, (None, scan_id) if clean.
    Raises exception on error or timeout.
    """
    if not text:
        return None, None

    document = Document(path='prompt-content.txt', content=text, is_git_diff_format=False)
    scan_ctx = _setup_scan_context(ctx)
    timeout_seconds = timeout_ms / 1000.0
    return _perform_scan(scan_ctx, [document], get_scan_parameters(scan_ctx, None), timeout_seconds)


def _scan_path_for_secrets(ctx: typer.Context, file_path: str, policy: dict) -> tuple[Optional[str], Optional[str]]:
    """
    Scan a file path for secrets.

    Returns tuple of (violation_summary, scan_id) if secrets found, (None, scan_id) if clean.
    Raises exception on error or timeout.
    """
    if not file_path or not os.path.exists(file_path):
        return None, None

    with open(file_path, encoding='utf-8', errors='replace') as f:
        content = f.read()

    # Truncate content based on policy max_bytes
    max_bytes = get_policy_value(policy, 'secrets', 'max_bytes', default=200000)
    content = truncate_utf8(content, max_bytes)

    # Get timeout from policy
    timeout_ms = get_policy_value(policy, 'secrets', 'timeout_ms', default=30000)
    timeout_seconds = timeout_ms / 1000.0

    document = Document(path=os.path.basename(file_path), content=content, is_git_diff_format=False)
    scan_ctx = _setup_scan_context(ctx)
    return _perform_scan(scan_ctx, [document], get_scan_parameters(scan_ctx, (file_path,)), timeout_seconds)
