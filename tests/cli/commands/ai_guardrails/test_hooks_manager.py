"""Tests for AI guardrails hooks manager."""

from cycode.cli.apps.ai_guardrails.hooks_manager import is_cycode_hook_entry


def test_is_cycode_hook_entry_cursor_format() -> None:
    """Test detecting Cycode hook in Cursor format (flat command)."""
    entry = {'command': 'cycode ai-guardrails scan'}
    assert is_cycode_hook_entry(entry) is True

    entry = {'command': 'cycode ai-guardrails scan --some-flag'}
    assert is_cycode_hook_entry(entry) is True


def test_is_cycode_hook_entry_claude_code_format() -> None:
    """Test detecting Cycode hook in Claude Code format (nested)."""
    entry = {
        'hooks': [{'type': 'command', 'command': 'cycode ai-guardrails scan --ide claude-code'}],
    }
    assert is_cycode_hook_entry(entry) is True

    entry = {
        'matcher': 'Read',
        'hooks': [{'type': 'command', 'command': 'cycode ai-guardrails scan --ide claude-code'}],
    }
    assert is_cycode_hook_entry(entry) is True


def test_is_cycode_hook_entry_non_cycode() -> None:
    """Test that non-Cycode hooks are not detected."""
    # Cursor format
    entry = {'command': 'some-other-command'}
    assert is_cycode_hook_entry(entry) is False

    # Claude Code format
    entry = {
        'hooks': [{'type': 'command', 'command': 'some-other-command'}],
    }
    assert is_cycode_hook_entry(entry) is False

    # Empty entry
    entry = {}
    assert is_cycode_hook_entry(entry) is False


def test_is_cycode_hook_entry_partial_match() -> None:
    """Test partial command match."""
    # Should match if command contains 'cycode ai-guardrails scan'
    entry = {'command': '/usr/local/bin/cycode ai-guardrails scan'}
    assert is_cycode_hook_entry(entry) is True

    entry = {'command': 'cycode ai-guardrails scan --verbose'}
    assert is_cycode_hook_entry(entry) is True
