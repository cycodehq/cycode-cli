"""Common utilities for AI guardrails commands."""

import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

console = Console()


def validate_scope(scope: str, allowed_scopes: tuple[str, ...] = ('user', 'repo')) -> None:
    """Validate scope parameter."""
    if scope not in allowed_scopes:
        scopes_list = ', '.join(f'"{s}"' for s in allowed_scopes)
        console.print(f'[red]Error:[/] Invalid scope. Use {scopes_list}.', style='bold red')
        raise typer.Exit(1)


def resolve_repo_path(scope: str, repo_path: Optional[Path]) -> Optional[Path]:
    """Default repo_path to cwd for 'repo' scope; leave None for 'user' scope."""
    if scope == 'repo' and repo_path is None:
        return Path(os.getcwd())
    return repo_path
