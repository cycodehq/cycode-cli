"""Hook handlers for AI IDE events.

Each handler receives a unified payload and policy, applies the scan + policy
logic, and returns a canonical ``HookDecision``. ``scan_command`` translates
that decision into the IDE-specific JSON response via ``IDE.build_hook_response``.

Handlers are agent-agnostic by design — adding a new IDE doesn't require
touching any handler in this module.
"""

import json
import os
from dataclasses import dataclass
from multiprocessing.pool import ThreadPool
from multiprocessing.pool import TimeoutError as PoolTimeoutError
from typing import Callable, Optional

import typer

from cycode.cli.apps.ai_guardrails.consts import PolicyMode
from cycode.cli.apps.ai_guardrails.ides.base import HookDecision
from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.policy import get_policy_value
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


HandlerFn = Callable[[typer.Context, AIHookPayload, dict], HookDecision]


def handle_before_submit_prompt(ctx: typer.Context, payload: AIHookPayload, policy: dict) -> HookDecision:
    """Scan prompt text for secrets before it's sent to the AI model."""
    ai_client = ctx.obj['ai_security_client']

    prompt_config = get_policy_value(policy, 'prompt', default={})
    if not get_policy_value(prompt_config, 'enabled', default=True):
        ai_client.create_event(payload, AiHookEventType.PROMPT, AIHookOutcome.ALLOWED)
        return HookDecision.allow(AiHookEventType.PROMPT)

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
                return HookDecision.deny(AiHookEventType.PROMPT, user_message)
            outcome = AIHookOutcome.WARNED
        return HookDecision.allow(AiHookEventType.PROMPT)
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


def handle_before_read_file(ctx: typer.Context, payload: AIHookPayload, policy: dict) -> HookDecision:
    """Block sensitive paths and scan file content for secrets."""
    ai_client = ctx.obj['ai_security_client']

    file_read_config = get_policy_value(policy, 'file_read', default={})
    if not get_policy_value(file_read_config, 'enabled', default=True):
        ai_client.create_event(payload, AiHookEventType.FILE_READ, AIHookOutcome.ALLOWED)
        return HookDecision.allow(AiHookEventType.FILE_READ)

    mode = get_policy_value(policy, 'mode', default=PolicyMode.BLOCK)
    file_path = payload.file_path or ''
    action = get_policy_value(file_read_config, 'action', default=PolicyMode.BLOCK)

    scan_id = None
    block_reason = None
    outcome = AIHookOutcome.ALLOWED
    error_message = None

    try:
        is_sensitive_path = is_denied_path(file_path, policy)
        if is_sensitive_path:
            block_reason = BlockReason.SENSITIVE_PATH
            if mode == PolicyMode.BLOCK and action == PolicyMode.BLOCK:
                outcome = AIHookOutcome.BLOCKED
                user_message = f'Cycode blocked sending {file_path} to the AI (sensitive path policy).'
                return HookDecision.deny(
                    AiHookEventType.FILE_READ,
                    user_message,
                    'This file path is classified as sensitive; do not read/send it to the model.',
                )
            # Warn mode: if content scan is enabled, emit a separate event for the
            # sensitive path so the finally block can independently track the scan result.
            outcome = AIHookOutcome.WARNED
            if get_policy_value(file_read_config, 'scan_content', default=True):
                ai_client.create_event(
                    payload,
                    AiHookEventType.FILE_READ,
                    outcome,
                    block_reason=BlockReason.SENSITIVE_PATH,
                    file_path=payload.file_path,
                )
                block_reason = None
                outcome = AIHookOutcome.ALLOWED

        if get_policy_value(file_read_config, 'scan_content', default=True):
            violation_summary, scan_id = _scan_path_for_secrets(ctx, file_path, policy)
            if violation_summary:
                block_reason = BlockReason.SECRETS_IN_FILE
                if mode == PolicyMode.BLOCK and action == PolicyMode.BLOCK:
                    outcome = AIHookOutcome.BLOCKED
                    user_message = f'Cycode blocked reading {file_path}. {violation_summary}'
                    return HookDecision.deny(
                        AiHookEventType.FILE_READ,
                        user_message,
                        'Secrets detected; do not send this file to the model.',
                    )
                outcome = AIHookOutcome.WARNED
                user_message = f'Cycode detected secrets in {file_path}. {violation_summary}'
                return HookDecision.ask(
                    AiHookEventType.FILE_READ,
                    user_message,
                    'Possible secrets detected; proceed with caution.',
                )

        if is_sensitive_path:
            user_message = f'Cycode flagged {file_path} as sensitive. Allow reading?'
            return HookDecision.ask(
                AiHookEventType.FILE_READ,
                user_message,
                'This file path is classified as sensitive; proceed with caution.',
            )

        return HookDecision.allow(AiHookEventType.FILE_READ)
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
            file_path=payload.file_path,
        )


@dataclass(frozen=True)
class _ArgScanFeature:
    """Configuration for a "scan some text and decide" event.

    MCP execution and command exec share identical scan-and-decide logic;
    only the policy key, event type, and user-facing messages differ.
    """

    policy_key: str  # 'mcp' or 'command_exec'
    scan_key: str  # 'scan_arguments' or 'scan_command'
    event_type: AiHookEventType
    block_reason: BlockReason
    deny_message: Callable[[str], str]
    deny_agent_message: str
    ask_message: Callable[[str], str]
    ask_agent_message: str


def _handle_arg_scan(
    ctx: typer.Context,
    payload: AIHookPayload,
    policy: dict,
    feature: _ArgScanFeature,
    scan_text: str,
) -> HookDecision:
    """Shared scan + decision flow for MCP_EXECUTION and COMMAND_EXEC events."""
    ai_client = ctx.obj['ai_security_client']

    feature_config = get_policy_value(policy, feature.policy_key, default={})
    if not get_policy_value(feature_config, 'enabled', default=True):
        ai_client.create_event(payload, feature.event_type, AIHookOutcome.ALLOWED)
        return HookDecision.allow(feature.event_type)

    mode = get_policy_value(policy, 'mode', default=PolicyMode.BLOCK)
    max_bytes = get_policy_value(policy, 'secrets', 'max_bytes', default=200000)
    timeout_ms = get_policy_value(policy, 'secrets', 'timeout_ms', default=30000)
    clipped = truncate_utf8(scan_text, max_bytes)
    action = get_policy_value(feature_config, 'action', default=PolicyMode.BLOCK)

    scan_id = None
    block_reason = None
    outcome = AIHookOutcome.ALLOWED
    error_message = None

    try:
        if get_policy_value(feature_config, feature.scan_key, default=True):
            violation_summary, scan_id = _scan_text_for_secrets(ctx, clipped, timeout_ms)
            if violation_summary:
                block_reason = feature.block_reason
                if mode == PolicyMode.BLOCK and action == PolicyMode.BLOCK:
                    outcome = AIHookOutcome.BLOCKED
                    return HookDecision.deny(
                        feature.event_type,
                        feature.deny_message(violation_summary),
                        feature.deny_agent_message,
                    )
                outcome = AIHookOutcome.WARNED
                return HookDecision.ask(
                    feature.event_type,
                    feature.ask_message(violation_summary),
                    feature.ask_agent_message,
                )

        return HookDecision.allow(feature.event_type)
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
            feature.event_type,
            outcome,
            scan_id=scan_id,
            block_reason=block_reason,
            error_message=error_message,
        )


def handle_before_mcp_execution(ctx: typer.Context, payload: AIHookPayload, policy: dict) -> HookDecision:
    """Scan MCP tool arguments for secrets before execution."""
    tool = payload.mcp_tool_name or 'unknown'
    args = payload.mcp_arguments or {}
    args_text = args if isinstance(args, str) else json.dumps(args)
    return _handle_arg_scan(
        ctx,
        payload,
        policy,
        _ArgScanFeature(
            policy_key='mcp',
            scan_key='scan_arguments',
            event_type=AiHookEventType.MCP_EXECUTION,
            block_reason=BlockReason.SECRETS_IN_MCP_ARGS,
            deny_message=lambda v: f'Cycode blocked MCP tool call "{tool}". {v}',
            deny_agent_message='Do not pass secrets to tools. Use secret references (name/id) instead.',
            ask_message=lambda v: f'{v} in MCP tool call "{tool}". Allow execution?',
            ask_agent_message='Possible secrets detected in tool arguments; proceed with caution.',
        ),
        scan_text=args_text,
    )


def get_handler_for_event(event_type: str) -> Optional[HandlerFn]:
    """Look up the handler for a canonical event type."""
    handlers: dict[str, HandlerFn] = {
        AiHookEventType.PROMPT.value: handle_before_submit_prompt,
        AiHookEventType.FILE_READ.value: handle_before_read_file,
        AiHookEventType.MCP_EXECUTION.value: handle_before_mcp_execution,
    }
    return handlers.get(event_type)


def _setup_scan_context(ctx: typer.Context) -> typer.Context:
    """Set up minimal context for scan_documents without progress bars or printing."""
    ctx.obj['progress_bar'] = DummyProgressBar([ScanProgressBarSection])
    ctx.obj['sync'] = True
    ctx.obj['scan_type'] = ScanTypeOption.SECRET
    ctx.obj['severity_threshold'] = SeverityOption.INFO
    ctx.info_name = 'ai_guardrails'
    return ctx


def _perform_scan(
    ctx: typer.Context, documents: list[Document], scan_parameters: dict, timeout_seconds: float
) -> tuple[Optional[str], Optional[str]]:
    """Run a scan on documents, returning (violation_summary, scan_id).

    Raises on scan failure / timeout so the fail-open policy can take over.
    """
    if not documents:
        return None, None

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

    if local_scan_result.detections_count > 0:
        violation_summary = build_violation_summary([local_scan_result])
        return violation_summary, scan_id

    return None, scan_id


def _scan_text_for_secrets(ctx: typer.Context, text: str, timeout_ms: int) -> tuple[Optional[str], Optional[str]]:
    """Scan text content for secrets using Cycode CLI."""
    if not text:
        return None, None

    document = Document(path='prompt-content.txt', content=text, is_git_diff_format=False)
    scan_ctx = _setup_scan_context(ctx)
    timeout_seconds = timeout_ms / 1000.0
    return _perform_scan(scan_ctx, [document], get_scan_parameters(scan_ctx, None), timeout_seconds)


def _scan_path_for_secrets(ctx: typer.Context, file_path: str, policy: dict) -> tuple[Optional[str], Optional[str]]:
    """Scan a file path for secrets."""
    if not file_path or not os.path.isfile(file_path):
        return None, None

    max_bytes = get_policy_value(policy, 'secrets', 'max_bytes', default=200000)

    with open(file_path, encoding='utf-8', errors='replace') as f:
        content = f.read(max_bytes)

    timeout_ms = get_policy_value(policy, 'secrets', 'timeout_ms', default=30000)
    timeout_seconds = timeout_ms / 1000.0

    document = Document(path=os.path.basename(file_path), content=content, is_git_diff_format=False)
    scan_ctx = _setup_scan_context(ctx)
    return _perform_scan(scan_ctx, [document], get_scan_parameters(scan_ctx, (file_path,)), timeout_seconds)
