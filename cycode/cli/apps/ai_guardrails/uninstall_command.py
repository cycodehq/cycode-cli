"""Uninstall command for AI guardrails hooks."""

from pathlib import Path
from typing import Annotated, Optional

import typer

from cycode.cli.apps.ai_guardrails.command_utils import (
    console,
    resolve_repo_path,
    validate_and_parse_ide,
    validate_scope,
)
from cycode.cli.apps.ai_guardrails.consts import IDE_CONFIGS
from cycode.cli.apps.ai_guardrails.hooks_manager import uninstall_hooks
from cycode.cli.utils.sentry import add_breadcrumb


def uninstall_command(
    ctx: typer.Context,
    scope: Annotated[
        str,
        typer.Option(
            '--scope',
            '-s',
            help='Uninstall scope: "user" for user-level hooks, "repo" for repository-level hooks.',
        ),
    ] = 'user',
    ide: Annotated[
        str,
        typer.Option(
            '--ide',
            help='IDE to uninstall hooks from (e.g., "cursor"). Defaults to cursor.',
        ),
    ] = 'cursor',
    repo_path: Annotated[
        Optional[Path],
        typer.Option(
            '--repo-path',
            help='Repository path for repo-scoped uninstallation (defaults to current directory).',
            exists=True,
            file_okay=False,
            dir_okay=True,
            resolve_path=True,
        ),
    ] = None,
) -> None:
    """Remove AI guardrails hooks from supported IDEs.

    This command removes Cycode hooks from the IDE's hooks configuration.
    Other hooks (if any) will be preserved.

    Examples:
        cycode ai-guardrails uninstall                    # Remove user-level hooks
        cycode ai-guardrails uninstall --scope repo       # Remove repo-level hooks
        cycode ai-guardrails uninstall --ide cursor       # Uninstall from Cursor IDE
    """
    add_breadcrumb('ai-guardrails-uninstall')

    # Validate inputs
    validate_scope(scope)
    repo_path = resolve_repo_path(scope, repo_path)
    ide_type = validate_and_parse_ide(ide)
    ide_name = IDE_CONFIGS[ide_type].name
    success, message = uninstall_hooks(scope, repo_path, ide=ide_type)

    if success:
        console.print(f'[green]✓[/] {message}')
        console.print()
        console.print(f'[dim]Restart {ide_name} for changes to take effect.[/]')
    else:
        console.print(f'[red]✗[/] {message}', style='bold red')
        raise typer.Exit(1)
