"""Unified payload object for AI hook events from different tools."""

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cycode.cli.apps.ai_guardrails.consts import AIIDEType
from cycode.cli.apps.ai_guardrails.scan.types import (
    CLAUDE_CODE_EVENT_MAPPING,
    CLAUDE_CODE_EVENT_NAMES,
    CURSOR_EVENT_MAPPING,
    CURSOR_EVENT_NAMES,
    AiHookEventType,
)


def _reverse_readline(path: Path, buf_size: int = 8192) -> Iterator[str]:
    """Read a file line by line from the end without loading entire file into memory.

    Yields lines in reverse order (last line first).
    """
    with path.open('rb') as f:
        f.seek(0, 2)  # Seek to end
        file_size = f.tell()
        if file_size == 0:
            return

        remaining = file_size
        buffer = b''

        while remaining > 0:
            # Read a chunk from the end
            read_size = min(buf_size, remaining)
            remaining -= read_size
            f.seek(remaining)
            chunk = f.read(read_size)
            buffer = chunk + buffer

            # Yield complete lines from buffer
            while b'\n' in buffer:
                # Find the last newline
                newline_pos = buffer.rfind(b'\n')
                if newline_pos == len(buffer) - 1:
                    # Trailing newline, look for previous one
                    newline_pos = buffer.rfind(b'\n', 0, newline_pos)
                    if newline_pos == -1:
                        break
                # Yield the line after this newline
                line = buffer[newline_pos + 1 :]
                buffer = buffer[: newline_pos + 1]
                if line.strip():
                    yield line.decode('utf-8', errors='replace')

        # Yield any remaining content as the first line of the file
        if buffer.strip():
            yield buffer.decode('utf-8', errors='replace')


def _extract_model(entry: dict) -> Optional[str]:
    """Extract model from a transcript entry (top level or nested in message)."""
    return entry.get('model') or (entry.get('message') or {}).get('model')


def _extract_generation_id(entry: dict) -> Optional[str]:
    """Extract generation ID from a user-type transcript entry."""
    if entry.get('type') == 'user':
        return entry.get('uuid')
    return None


def _extract_from_claude_transcript(
    transcript_path: str,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract IDE version, model, and latest generation ID from Claude Code transcript file.

    The transcript is a JSONL file where each line is a JSON object.
    We look for 'version' (IDE version), 'model', and 'uuid' (generation ID) fields.
    The generation_id is the UUID of the latest 'user' type message.

    Scans from end to start since latest entries are at the end.
    Uses reverse reading to avoid loading entire file into memory.

    Returns:
        Tuple of (ide_version, model, generation_id), any may be None if not found.
    """
    if not transcript_path:
        return None, None, None

    path = Path(transcript_path)
    if not path.exists():
        return None, None, None

    ide_version = None
    model = None
    generation_id = None

    try:
        for line in _reverse_readline(path):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                ide_version = ide_version or entry.get('version')
                model = model or _extract_model(entry)
                generation_id = generation_id or _extract_generation_id(entry)

                if ide_version and model and generation_id:
                    break
            except json.JSONDecodeError:
                continue
    except OSError:
        pass

    return ide_version, model, generation_id


@dataclass
class AIHookPayload:
    """Unified payload object that normalizes field names from different AI tools."""

    # Event identification
    event_name: str  # Canonical event type (e.g., 'prompt', 'file_read', 'mcp_execution')
    conversation_id: Optional[str] = None
    generation_id: Optional[str] = None

    # User and IDE information
    ide_user_email: Optional[str] = None
    model: Optional[str] = None
    ide_provider: str = None  # AIIDEType value (e.g., 'cursor', 'claude-code')
    ide_version: Optional[str] = None

    # Event-specific data
    prompt: Optional[str] = None  # For prompt events
    file_path: Optional[str] = None  # For file_read events
    mcp_server_name: Optional[str] = None  # For mcp_execution events
    mcp_tool_name: Optional[str] = None  # For mcp_execution events
    mcp_arguments: Optional[dict] = None  # For mcp_execution events

    @classmethod
    def from_cursor_payload(cls, payload: dict) -> 'AIHookPayload':
        """Create AIHookPayload from Cursor IDE payload.

        Maps Cursor-specific event names to canonical event types.
        """
        cursor_event_name = payload.get('hook_event_name', '')
        # Map Cursor event name to canonical type, fallback to original if not found
        canonical_event = CURSOR_EVENT_MAPPING.get(cursor_event_name, cursor_event_name)

        return cls(
            event_name=canonical_event,
            conversation_id=payload.get('conversation_id'),
            generation_id=payload.get('generation_id'),
            ide_user_email=payload.get('user_email'),
            model=payload.get('model'),
            ide_provider=AIIDEType.CURSOR.value,
            ide_version=payload.get('cursor_version'),
            prompt=payload.get('prompt', ''),
            file_path=payload.get('file_path') or payload.get('path'),
            mcp_server_name=payload.get('command'),  # MCP server name
            mcp_tool_name=payload.get('tool_name') or payload.get('tool'),
            mcp_arguments=payload.get('arguments') or payload.get('tool_input') or payload.get('input'),
        )

    @classmethod
    def from_claude_code_payload(cls, payload: dict) -> 'AIHookPayload':
        """Create AIHookPayload from Claude Code IDE payload.

        Claude Code has a different structure:
        - hook_event_name: 'UserPromptSubmit' or 'PreToolUse'
        - For PreToolUse: tool_name determines if it's file read ('Read') or MCP ('mcp__*')
        - tool_input contains tool arguments (e.g., file_path for Read tool)
        - transcript_path points to JSONL file with version and model info
        """
        hook_event_name = payload.get('hook_event_name', '')
        tool_name = payload.get('tool_name', '')
        tool_input = payload.get('tool_input')

        if hook_event_name == 'UserPromptSubmit':
            canonical_event = AiHookEventType.PROMPT
        elif hook_event_name == 'PreToolUse':
            canonical_event = AiHookEventType.FILE_READ if tool_name == 'Read' else AiHookEventType.MCP_EXECUTION
        else:
            # Unknown event, use the raw event name
            canonical_event = CLAUDE_CODE_EVENT_MAPPING.get(hook_event_name, hook_event_name)

        # Extract file_path from tool_input for Read tool
        file_path = None
        if tool_name == 'Read' and isinstance(tool_input, dict):
            file_path = tool_input.get('file_path')

        # For MCP tools, the entire tool_input is the arguments
        mcp_arguments = tool_input if tool_name.startswith('mcp__') else None

        # Extract MCP server and tool name from tool_name (format: mcp__<server>__<tool>)
        mcp_server_name = None
        mcp_tool_name = None
        if tool_name.startswith('mcp__'):
            parts = tool_name.split('__')
            if len(parts) >= 2:
                mcp_server_name = parts[1]
            if len(parts) >= 3:
                mcp_tool_name = parts[2]

        # Extract IDE version, model, and generation ID from transcript file
        ide_version, model, generation_id = _extract_from_claude_transcript(payload.get('transcript_path'))

        return cls(
            event_name=canonical_event,
            conversation_id=payload.get('session_id'),
            generation_id=generation_id,
            ide_user_email=None,  # Claude Code doesn't provide this in hook payload
            model=model,
            ide_provider=AIIDEType.CLAUDE_CODE.value,
            ide_version=ide_version,
            prompt=payload.get('prompt', ''),
            file_path=file_path,
            mcp_server_name=mcp_server_name,
            mcp_tool_name=mcp_tool_name,
            mcp_arguments=mcp_arguments,
        )

    @staticmethod
    def is_payload_for_ide(payload: dict, ide: str) -> bool:
        """Check if the payload's event name matches the expected IDE.

        This prevents double-processing when Cursor reads Claude Code hooks
        or vice versa. If the payload's hook_event_name doesn't match the
        expected IDE's event names, we should skip processing.

        Args:
            payload: The raw payload from the IDE
            ide: The IDE name or AIIDEType enum value

        Returns:
            True if the payload matches the IDE, False otherwise.
        """
        hook_event_name = payload.get('hook_event_name', '')

        if ide == AIIDEType.CLAUDE_CODE:
            return hook_event_name in CLAUDE_CODE_EVENT_NAMES
        if ide == AIIDEType.CURSOR:
            return hook_event_name in CURSOR_EVENT_NAMES

        # Unknown IDE, allow processing
        return True

    @classmethod
    def from_payload(cls, payload: dict, tool: str = AIIDEType.CURSOR.value) -> 'AIHookPayload':
        """Create AIHookPayload from any tool's payload.

        Args:
            payload: The raw payload from the IDE
            tool: The IDE/tool name or AIIDEType enum value

        Returns:
            AIHookPayload instance

        Raises:
            ValueError: If the tool is not supported
        """
        if tool == AIIDEType.CURSOR:
            return cls.from_cursor_payload(payload)
        if tool == AIIDEType.CLAUDE_CODE:
            return cls.from_claude_code_payload(payload)
        raise ValueError(f'Unsupported IDE/tool: {tool}')
