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
from cycode.cli.apps.ai_guardrails.consts import IDE_CONFIGS, AIIDEType
from cycode.cli.apps.ai_guardrails.hooks_manager import uninstall_hooks


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
            help='IDE to uninstall hooks from (e.g., "cursor", "claude-code", "all"). Defaults to cursor.',
        ),
    ] = AIIDEType.CURSOR.value,
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
        cycode ai-guardrails uninstall --ide all          # Uninstall from all supported IDEs
    """
    # Validate inputs
    validate_scope(scope)
    repo_path = resolve_repo_path(scope, repo_path)
    ide_type = validate_and_parse_ide(ide)

    ides_to_uninstall: list[AIIDEType] = list(AIIDEType) if ide_type is None else [ide_type]

    results: list[tuple[str, bool, str]] = []
    for current_ide in ides_to_uninstall:
        ide_name = IDE_CONFIGS[current_ide].name
        success, message = uninstall_hooks(scope, repo_path, ide=current_ide)
        results.append((ide_name, success, message))

    # Report results for each IDE
    any_success = False
    all_success = True
    for _ide_name, success, message in results:
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
