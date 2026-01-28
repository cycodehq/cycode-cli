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
from cycode.cli.apps.ai_guardrails.consts import IDE_CONFIGS
from cycode.cli.apps.ai_guardrails.hooks_manager import install_hooks
from cycode.cli.utils.sentry import add_breadcrumb


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
            help='IDE to install hooks for (e.g., "cursor"). Defaults to cursor.',
        ),
    ] = 'cursor',
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
        cycode ai-guardrails install --scope repo --repo-path /path/to/repo
    """
    add_breadcrumb('ai-guardrails-install')

    # Validate inputs
    validate_scope(scope)
    repo_path = resolve_repo_path(scope, repo_path)
    ide_type = validate_and_parse_ide(ide)
    ide_name = IDE_CONFIGS[ide_type].name
    success, message = install_hooks(scope, repo_path, ide=ide_type)

    if success:
        console.print(f'[green]✓[/] {message}')
        console.print()
        console.print('[bold]Next steps:[/]')
        console.print(f'1. Restart {ide_name} to activate the hooks')
        console.print('2. (Optional) Customize policy in ~/.cycode/ai-guardrails.yaml')
        console.print()
        console.print('[dim]The hooks will scan prompts, file reads, and MCP tool calls for secrets.[/]')
    else:
        console.print(f'[red]✗[/] {message}', style='bold red')
        raise typer.Exit(1)
