"""Tests for AI guardrails utility functions."""

from cycode.cli.apps.ai_guardrails.scan.utils import (
    is_denied_path,
    matches_glob,
    normalize_path,
)


def test_normalize_path_rejects_escape() -> None:
    """Test that paths attempting to escape are rejected."""
    path = '../../../etc/passwd'
    result = normalize_path(path)

    assert result == ''


def test_normalize_path_empty() -> None:
    """Test normalizing empty path."""
    result = normalize_path('')

    assert result == ''


def test_matches_glob_simple() -> None:
    """Test simple glob pattern matching."""
    assert matches_glob('secret.env', '*.env') is True
    assert matches_glob('secret.txt', '*.env') is False


def test_matches_glob_recursive() -> None:
    """Test recursive glob pattern with **."""
    assert matches_glob('path/to/secret.env', '**/*.env') is True
    # Note: '**/*.env' requires at least one path separator, so 'secret.env' won't match
    assert matches_glob('secret.env', '*.env') is True  # Use non-recursive pattern instead
    assert matches_glob('path/to/file.txt', '**/*.env') is False


def test_matches_glob_directory() -> None:
    """Test matching files in specific directories."""
    assert matches_glob('.env', '.env') is True
    assert matches_glob('config/.env', '**/.env') is True
    assert matches_glob('other/file', '**/.env') is False


def test_matches_glob_case_insensitive() -> None:
    """Test that glob matching handles case variations."""
    # Case-insensitive matching for cross-platform compatibility
    assert matches_glob('secret.env', '*.env') is True
    assert matches_glob('SECRET.ENV', '*.env') is True  # Uppercase path matches lowercase pattern
    assert matches_glob('Secret.Env', '*.env') is True  # Mixed case matches
    assert matches_glob('secret.env', '*.ENV') is True  # Lowercase path matches uppercase pattern
    assert matches_glob('SECRET.ENV', '*.ENV') is True  # Both uppercase match


def test_matches_glob_empty_inputs() -> None:
    """Test glob matching with empty inputs."""
    assert matches_glob('', '*.env') is False
    assert matches_glob('file.env', '') is False
    assert matches_glob('', '') is False


def test_matches_glob_with_traversal_attempt() -> None:
    """Test that path traversal is normalized before matching."""
    # Path traversal attempts should be normalized
    assert matches_glob('../secret.env', '*.env') is False


def test_is_denied_path_with_deny_globs() -> None:
    """Test path denial with deny_globs policy."""
    policy = {'file_read': {'deny_globs': ['*.env', '.git/*', '**/secrets/*']}}

    assert is_denied_path('.env', policy) is True
    # Note: Path.match('*.env') matches paths ending with .env, including nested paths
    assert is_denied_path('config/.env', policy) is True  # Matches *.env
    assert is_denied_path('.git/config', policy) is True  # Matches .git/*
    assert is_denied_path('app/secrets/api_keys.txt', policy) is True  # Matches **/secrets/*
    assert is_denied_path('app/config.yaml', policy) is False


def test_is_denied_path_nested_patterns() -> None:
    """Test denial with various nesting patterns."""
    policy = {'file_read': {'deny_globs': ['*.key', '**/*.key', 'config/*.env']}}

    # *.key matches .key files at root level, **/*.key for nested
    assert is_denied_path('private.key', policy) is True
    assert is_denied_path('app/private.key', policy) is True
    # config/*.env only matches .env files directly in config/
    assert is_denied_path('config/app.env', policy) is True
    assert is_denied_path('config/sub/app.env', policy) is False  # Not direct child
    assert is_denied_path('app/config.yaml', policy) is False


def test_is_denied_path_empty_globs() -> None:
    """Test that empty deny_globs list denies nothing."""
    policy = {'file_read': {'deny_globs': []}}

    assert is_denied_path('.env', policy) is False
    assert is_denied_path('any/path', policy) is False


def test_is_denied_path_no_policy() -> None:
    """Test denial with missing policy configuration."""
    policy = {}

    assert is_denied_path('.env', policy) is False


def test_is_denied_path_empty_path() -> None:
    """Test denial check with empty path."""
    policy = {'file_read': {'deny_globs': ['*.env']}}

    assert is_denied_path('', policy) is False
