"""Install command for AI guardrails hooks."""

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
from cycode.cli.apps.ai_guardrails.hooks_manager import install_hooks


def install_command(
    ctx: typer.Context,
    scope: Annotated[
        str,
        typer.Option(
            '--scope',
            '-s',
            help='Installation scope: "user" for all projects, "repo" for current repository only.',
        ),
    ] = 'user',
    ide: Annotated[
        str,
        typer.Option(
            '--ide',
            help='IDE to install hooks for (e.g., "cursor", "claude-code", or "all" for all IDEs). Defaults to cursor.',
        ),
    ] = AIIDEType.CURSOR.value,
    repo_path: Annotated[
        Optional[Path],
        typer.Option(
            '--repo-path',
            help='Repository path for repo-scoped installation (defaults to current directory).',
            exists=True,
            file_okay=False,
            dir_okay=True,
            resolve_path=True,
        ),
    ] = None,
) -> None:
    """Install AI guardrails hooks for supported IDEs.

    This command configures the specified IDE to use Cycode for scanning prompts, file reads,
    and MCP tool calls for secrets before they are sent to AI models.

    Examples:
        cycode ai-guardrails install                    # Install for all projects (user scope)
        cycode ai-guardrails install --scope repo       # Install for current repo only
        cycode ai-guardrails install --ide cursor       # Install for Cursor IDE
        cycode ai-guardrails install --ide all          # Install for all supported IDEs
        cycode ai-guardrails install --scope repo --repo-path /path/to/repo
    """
    # Validate inputs
    validate_scope(scope)
    repo_path = resolve_repo_path(scope, repo_path)
    ide_type = validate_and_parse_ide(ide)

    ides_to_install: list[AIIDEType] = list(AIIDEType) if ide_type is None else [ide_type]

    results: list[tuple[str, bool, str]] = []
    for current_ide in ides_to_install:
        ide_name = IDE_CONFIGS[current_ide].name
        success, message = install_hooks(scope, repo_path, ide=current_ide)
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
        console.print('[bold]Next steps:[/]')
        successful_ides = [name for name, success, _ in results if success]
        ide_list = ', '.join(successful_ides)
        console.print(f'1. Restart {ide_list} to activate the hooks')
        console.print('2. (Optional) Customize policy in ~/.cycode/ai-guardrails.yaml')
        console.print()
        console.print('[dim]The hooks will scan prompts, file reads, and MCP tool calls for secrets.[/]')

    if not all_success:
        raise typer.Exit(1)
