"""Uninstall command for AI guardrails hooks."""

from pathlib import Path
from typing import Annotated, Optional

import typer

from cycode.cli.apps.ai_guardrails.command_utils import console, resolve_repo_path, validate_scope
from cycode.cli.apps.ai_guardrails.hooks_manager import uninstall_hooks
from cycode.cli.apps.ai_guardrails.ides import DEFAULT_IDE_NAME, IDES, resolve_ides


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
            help=f'IDE to uninstall hooks from ({", ".join(IDES)}, or "all").',
        ),
    ] = DEFAULT_IDE_NAME,
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

    Removes Cycode hooks from the IDE's hooks configuration. Other hooks
    (if any) are preserved.

    Examples:
        cycode ai-guardrails uninstall                    # Remove user-level hooks
        cycode ai-guardrails uninstall --scope repo       # Remove repo-level hooks
        cycode ai-guardrails uninstall --ide claude-code  # Uninstall from a specific IDE
        cycode ai-guardrails uninstall --ide all          # Uninstall from every supported IDE
    """
    validate_scope(scope)
    repo_path = resolve_repo_path(scope, repo_path)
    ides_to_uninstall = resolve_ides(ide)

    results: list[tuple[str, bool, str]] = []
    for current_ide in ides_to_uninstall:
        success, message = uninstall_hooks(current_ide, scope, repo_path)
        results.append((current_ide.display_name, success, message))

    any_success = False
    all_success = True
    for _name, success, message in results:
        if success:
            console.print(f'[green]✓[/] {message}')
            any_success = True
        else:
            console.print(f'[red]✗[/] {message}', style='bold red')
            all_success = False

    if any_success:
        console.print()
        successful_ides = [name for name, success, _ in results if success]
        ide_list = ', '.join(successful_ides)
        console.print(f'[dim]Restart {ide_list} for changes to take effect.[/]')

    if not all_success:
        raise typer.Exit(1)
