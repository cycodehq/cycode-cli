"""Tests for AI guardrails command utilities."""

import pytest
import typer

from cycode.cli.apps.ai_guardrails.command_utils import (
    validate_and_parse_ide,
    validate_scope,
)
from cycode.cli.apps.ai_guardrails.consts import AIIDEType


def test_validate_and_parse_ide_valid() -> None:
    """Test parsing valid IDE names."""
    assert validate_and_parse_ide('cursor') == AIIDEType.CURSOR
    assert validate_and_parse_ide('CURSOR') == AIIDEType.CURSOR
    assert validate_and_parse_ide('CuRsOr') == AIIDEType.CURSOR


def test_validate_and_parse_ide_invalid() -> None:
    """Test that invalid IDE raises typer.Exit."""
    with pytest.raises(typer.Exit) as exc_info:
        validate_and_parse_ide('invalid_ide')
    assert exc_info.value.exit_code == 1


def test_validate_scope_valid_default() -> None:
    """Test validating valid scope with default allowed scopes."""
    # Should not raise any exception
    validate_scope('user')
    validate_scope('repo')


def test_validate_scope_invalid_default() -> None:
    """Test that invalid scope raises typer.Exit with default allowed scopes."""
    with pytest.raises(typer.Exit) as exc_info:
        validate_scope('invalid')
    assert exc_info.value.exit_code == 1

    with pytest.raises(typer.Exit) as exc_info:
        validate_scope('all')  # 'all' not in default allowed scopes
    assert exc_info.value.exit_code == 1


def test_validate_scope_valid_custom() -> None:
    """Test validating scope with custom allowed scopes."""
    # Should not raise any exception
    validate_scope('user', allowed_scopes=('user', 'repo', 'all'))
    validate_scope('repo', allowed_scopes=('user', 'repo', 'all'))
    validate_scope('all', allowed_scopes=('user', 'repo', 'all'))


def test_validate_scope_invalid_custom() -> None:
    """Test that invalid scope raises typer.Exit with custom allowed scopes."""
    with pytest.raises(typer.Exit) as exc_info:
        validate_scope('invalid', allowed_scopes=('user', 'repo', 'all'))
    assert exc_info.value.exit_code == 1
