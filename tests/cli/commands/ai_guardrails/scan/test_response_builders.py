"""Tests for IDE response builders."""

import pytest

from cycode.cli.apps.ai_guardrails.scan.response_builders import (
    CursorResponseBuilder,
    IDEResponseBuilder,
    get_response_builder,
)


def test_cursor_response_builder_allow_permission() -> None:
    """Test Cursor allow permission response."""
    builder = CursorResponseBuilder()
    response = builder.allow_permission()

    assert response == {'permission': 'allow'}


def test_cursor_response_builder_deny_permission() -> None:
    """Test Cursor deny permission response with messages."""
    builder = CursorResponseBuilder()
    response = builder.deny_permission('User message', 'Agent message')

    assert response == {
        'permission': 'deny',
        'user_message': 'User message',
        'agent_message': 'Agent message',
    }


def test_cursor_response_builder_ask_permission() -> None:
    """Test Cursor ask permission response for warnings."""
    builder = CursorResponseBuilder()
    response = builder.ask_permission('Warning message', 'Agent warning')

    assert response == {
        'permission': 'ask',
        'user_message': 'Warning message',
        'agent_message': 'Agent warning',
    }


def test_cursor_response_builder_allow_prompt() -> None:
    """Test Cursor allow prompt response."""
    builder = CursorResponseBuilder()
    response = builder.allow_prompt()

    assert response == {'continue': True}


def test_cursor_response_builder_deny_prompt() -> None:
    """Test Cursor deny prompt response with message."""
    builder = CursorResponseBuilder()
    response = builder.deny_prompt('Secrets detected')

    assert response == {'continue': False, 'user_message': 'Secrets detected'}


def test_get_response_builder_cursor() -> None:
    """Test getting Cursor response builder."""
    builder = get_response_builder('cursor')

    assert isinstance(builder, CursorResponseBuilder)
    assert isinstance(builder, IDEResponseBuilder)


def test_get_response_builder_unsupported() -> None:
    """Test that unsupported IDE raises ValueError."""
    with pytest.raises(ValueError, match='Unsupported IDE: unknown'):
        get_response_builder('unknown')


def test_cursor_response_builder_is_singleton() -> None:
    """Test that getting the same builder returns the same instance."""
    builder1 = get_response_builder('cursor')
    builder2 = get_response_builder('cursor')

    assert builder1 is builder2
