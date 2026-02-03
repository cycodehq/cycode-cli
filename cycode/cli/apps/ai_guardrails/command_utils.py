"""Common utilities for AI guardrails commands."""

import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from cycode.cli.apps.ai_guardrails.consts import AIIDEType

console = Console()


def validate_and_parse_ide(ide: str) -> Optional[AIIDEType]:
    """Validate IDE parameter, returning None for 'all'.

    Args:
        ide: IDE name string (e.g., 'cursor', 'claude-code', 'all')

    Returns:
        AIIDEType enum value, or None if 'all' was specified

    Raises:
        typer.Exit: If IDE is invalid
    """
    if ide.lower() == 'all':
        return None
    try:
        return AIIDEType(ide.lower())
    except ValueError:
        valid_ides = ', '.join([ide_type.value for ide_type in AIIDEType])
        console.print(
            f'[red]Error:[/] Invalid IDE "{ide}". Supported IDEs: {valid_ides}, all',
            style='bold red',
        )
        raise typer.Exit(1) from None


def validate_scope(scope: str, allowed_scopes: tuple[str, ...] = ('user', 'repo')) -> None:
    """Validate scope parameter.

    Args:
        scope: Scope string to validate
        allowed_scopes: Tuple of allowed scope values

    Raises:
        typer.Exit: If scope is invalid
    """
    if scope not in allowed_scopes:
        scopes_list = ', '.join(f'"{s}"' for s in allowed_scopes)
        console.print(f'[red]Error:[/] Invalid scope. Use {scopes_list}.', style='bold red')
        raise typer.Exit(1)


def resolve_repo_path(scope: str, repo_path: Optional[Path]) -> Optional[Path]:
    """Resolve repository path, defaulting to current directory for repo scope.

    Args:
        scope: The command scope ('user' or 'repo')
        repo_path: Provided repo path or None

    Returns:
        Resolved Path for repo scope, None for user scope
    """
    if scope == 'repo' and repo_path is None:
        return Path(os.getcwd())
    return repo_path
