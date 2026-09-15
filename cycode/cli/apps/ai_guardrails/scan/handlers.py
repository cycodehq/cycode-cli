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
from typing import TYPE_CHECKING, Callable, NamedTuple, Optional

import typer

if TYPE_CHECKING:
    from cycode.cli.apps.ai_guardrails.scan.guardrail_config import GuardrailConfig

from cycode.cli.apps.ai_guardrails.consts import GuardrailsMode, PolicyMode
from cycode.cli.apps.ai_guardrails.ides.base import HookDecision
from cycode.cli.apps.ai_guardrails.scan.payload import AIHookPayload
from cycode.cli.apps.ai_guardrails.scan.policy import get_policy_value
from cycode.cli.apps.ai_guardrails.scan.types import (
    SECRETS_BLOCK_REASON_BY_EVENT_TYPE,
    AiHookEventType,
    AIHookOutcome,
    BlockReason,
)
from cycode.cli.apps.ai_guardrails.scan.utils import build_violation_summary, is_denied_path, truncate_utf8
from cycode.cli.apps.scan.code_scanner import _get_scan_documents_thread_func
from cycode.cli.apps.scan.scan_parameters import get_scan_parameters
from cycode.cli.cli_types import ScanTypeOption, SeverityOption
from cycode.cli.files_collector.file_excluder import is_path_configured_in_exclusions
from cycode.cli.models import Document
from cycode.cli.utils.host_info import get_hostname, get_serial_number
from cycode.cli.utils.progress_bar import DummyProgressBar, ScanProgressBarSection
from cycode.logger import get_logger

logger = get_logger('AI Guardrails')

HandlerFn = Callable[[typer.Context, AIHookPayload, dict], HookDecision]


class ScanOutcome(NamedTuple):
    """What one guardrail scan came back with; the verdict is the server's, which applied the tenant's floors."""

    violation_summary: Optional[str] = None
    scan_id: Optional[str] = None
    verdict: Optional[GuardrailsMode] = None


NO_SCAN = ScanOutcome()


def _parse_verdict(verdict: Optional[str]) -> Optional[GuardrailsMode]:
    """The server spells the verdict "Block"/"Report" and omits it when the scan found nothing to decide on."""
    if not verdict:
        return None
    try:
        return GuardrailsMode(verdict.lower())
    except ValueError:
        logger.debug('Ignoring unknown guardrail verdict, %s', {'verdict': verdict})
        return None


def handle_before_submit_prompt(ctx: typer.Context, payload: AIHookPayload, policy: dict) -> HookDecision:
    """Scan prompt text for secrets before it's sent to the AI model."""
    ai_client = ctx.obj['ai_security_client']

    prompt = payload.prompt or ''
    max_bytes = get_policy_value(policy, 'secrets', 'max_bytes', default=200000)
    timeout_ms = get_policy_value(policy, 'secrets', 'timeout_ms', default=30000)
    clipped = truncate_utf8(prompt, max_bytes)

    scan_id = None
    block_reason = None
    outcome = AIHookOutcome.ALLOWED
    error_message = None

    try:
        scan_outcome = _scan_text_for_secrets(
            ctx,
            clipped,
            timeout_ms,
            payload=payload,
            event_type=AiHookEventType.PROMPT,
        )
        scan_id = scan_outcome.scan_id

        if scan_outcome.violation_summary:
            block_reason = SECRETS_BLOCK_REASON_BY_EVENT_TYPE[AiHookEventType.PROMPT]
            if scan_outcome.verdict == GuardrailsMode.BLOCK:
                outcome = AIHookOutcome.BLOCKED
                user_message = f'Remove secrets before sending. {scan_outcome.violation_summary}'
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
    file_path = payload.file_path or ''
    path_mode = get_effective_mode(file_read_config, action_key='path_action')

    scan_id = None
    block_reason = None
    outcome = AIHookOutcome.ALLOWED
    error_message = None

    try:
        is_sensitive_path = is_denied_path(file_path, policy)
        if is_sensitive_path:
            block_reason = BlockReason.SENSITIVE_PATH
            if path_mode == GuardrailsMode.BLOCK:
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
            scan_outcome = _scan_path_for_secrets(ctx, file_path, policy, payload=payload)
            scan_id = scan_outcome.scan_id
            if scan_outcome.violation_summary:
                block_reason = SECRETS_BLOCK_REASON_BY_EVENT_TYPE[AiHookEventType.FILE_READ]
                if scan_outcome.verdict == GuardrailsMode.BLOCK:
                    outcome = AIHookOutcome.BLOCKED
                    user_message = f'Cycode blocked reading {file_path}. {scan_outcome.violation_summary}'
                    return HookDecision.deny(
                        AiHookEventType.FILE_READ,
                        user_message,
                        'Secrets detected; do not send this file to the model.',
                    )
                outcome = AIHookOutcome.WARNED
                user_message = f'Cycode detected secrets in {file_path}. {scan_outcome.violation_summary}'
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
    only the event type and user-facing messages differ.
    """

    event_type: AiHookEventType
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

    max_bytes = get_policy_value(policy, 'secrets', 'max_bytes', default=200000)
    timeout_ms = get_policy_value(policy, 'secrets', 'timeout_ms', default=30000)
    clipped = truncate_utf8(scan_text, max_bytes)

    scan_id = None
    block_reason = None
    outcome = AIHookOutcome.ALLOWED
    error_message = None

    try:
        scan_outcome = _scan_text_for_secrets(
            ctx,
            clipped,
            timeout_ms,
            payload=payload,
            event_type=feature.event_type,
        )
        scan_id = scan_outcome.scan_id
        if scan_outcome.violation_summary:
            block_reason = SECRETS_BLOCK_REASON_BY_EVENT_TYPE[feature.event_type]
            if scan_outcome.verdict == GuardrailsMode.BLOCK:
                outcome = AIHookOutcome.BLOCKED
                return HookDecision.deny(
                    feature.event_type,
                    feature.deny_message(scan_outcome.violation_summary),
                    feature.deny_agent_message,
                )
            outcome = AIHookOutcome.WARNED
            return HookDecision.ask(
                feature.event_type,
                feature.ask_message(scan_outcome.violation_summary),
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
            event_type=AiHookEventType.MCP_EXECUTION,
            deny_message=lambda v: f'Cycode blocked MCP tool call "{tool}". {v}',
            deny_agent_message='Do not pass secrets to tools. Use secret references (name/id) instead.',
            ask_message=lambda v: f'Allow MCP tool call "{tool}"? {v}',
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


def get_effective_mode(feature_config: dict, action_key: str = 'action') -> GuardrailsMode:
    """A guardrail's action is its matrix cell: block, or warn (report) for everything else."""
    action = get_policy_value(feature_config, action_key, default=PolicyMode.BLOCK)
    return GuardrailsMode.BLOCK if action == PolicyMode.BLOCK else GuardrailsMode.REPORT


def should_detach_scan(
    config: Optional['GuardrailConfig'],
    policy: dict,
    event_name: str,
    ide_name: Optional[str],
) -> bool:
    """Whether this event's scan is safe to run detached.

    Report mode never blocks, so nobody consumes the verdict. The platform config is the only
    mode source: without a cache the scan stays synchronous (never detach on an assumption).
    Fail-closed configs also stay synchronous: their deny on scan failure must reach the IDE.
    """
    if config is None:
        return False
    if not get_policy_value(policy, 'fail_open', default=True):
        return False
    return not config.can_event_block(event_name, ide_name)


def build_ai_guardrails_scan_parameters(
    ctx: typer.Context,
    paths: Optional[tuple[str, ...]],
    payload: AIHookPayload,
    event_type: AiHookEventType,
) -> dict:
    scan_parameters = get_scan_parameters(ctx, paths)
    scan_parameters.setdefault('metadata', {})['ai_guardrails'] = {
        'ide_provider': payload.ide_provider,
        'detection_source': SECRETS_BLOCK_REASON_BY_EVENT_TYPE[event_type].value,
        'device_id': get_serial_number(),
        'device_hostname': get_hostname(),
        'conversation_id': payload.conversation_id,
        'generation_id': payload.generation_id,
        'hook_event_id': payload.hook_event_id,
        'ide_user_email': payload.ide_user_email,
        'mcp_server_name': payload.mcp_server_name,
        'mcp_tool_name': payload.mcp_tool_name,
    }
    return scan_parameters


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
) -> ScanOutcome:
    """Run a scan on documents.

    Raises on scan failure / timeout so the fail-open policy can take over.
    """
    if not documents:
        return NO_SCAN

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
        return NO_SCAN

    violation_summary = build_violation_summary([local_scan_result]) if local_scan_result.issue_detected else None
    return ScanOutcome(
        violation_summary=violation_summary,
        scan_id=local_scan_result.scan_id,
        verdict=_parse_verdict(local_scan_result.verdict),
    )


def _scan_text_for_secrets(
    ctx: typer.Context,
    text: str,
    timeout_ms: int,
    payload: AIHookPayload,
    event_type: AiHookEventType,
) -> ScanOutcome:
    """Scan text content for secrets using Cycode CLI."""
    if not text:
        return NO_SCAN

    document = Document(path='prompt-content.txt', content=text, is_git_diff_format=False)
    scan_ctx = _setup_scan_context(ctx)
    timeout_seconds = timeout_ms / 1000.0
    scan_parameters = build_ai_guardrails_scan_parameters(scan_ctx, None, payload, event_type)
    return _perform_scan(scan_ctx, [document], scan_parameters, timeout_seconds)


def _scan_path_for_secrets(
    ctx: typer.Context,
    file_path: str,
    policy: dict,
    payload: AIHookPayload,
) -> ScanOutcome:
    """Scan a file path for secrets."""
    if not file_path or not os.path.isfile(file_path):
        return NO_SCAN

    if is_path_configured_in_exclusions(str(ScanTypeOption.SECRET), os.path.abspath(file_path)):
        logger.debug('Skipping scan; the path is in the ignore paths list, %s', {'file_path': file_path})
        return NO_SCAN

    max_bytes = get_policy_value(policy, 'secrets', 'max_bytes', default=200000)

    with open(file_path, encoding='utf-8', errors='replace') as f:
        content = f.read(max_bytes)

    timeout_ms = get_policy_value(policy, 'secrets', 'timeout_ms', default=30000)
    timeout_seconds = timeout_ms / 1000.0

    document = Document(path=os.path.basename(file_path), content=content, is_git_diff_format=False)
    scan_ctx = _setup_scan_context(ctx)
    scan_parameters = build_ai_guardrails_scan_parameters(scan_ctx, (file_path,), payload, AiHookEventType.FILE_READ)
    return _perform_scan(scan_ctx, [document], scan_parameters, timeout_seconds)
