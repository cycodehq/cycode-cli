"""Status command for AI guardrails hooks."""

import os
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.table import Table

from cycode.cli.apps.ai_guardrails.command_utils import console, validate_and_parse_ide, validate_scope
from cycode.cli.apps.ai_guardrails.consts import IDE_CONFIGS, AIIDEType
from cycode.cli.apps.ai_guardrails.hooks_manager import get_hooks_status


def status_command(
    ctx: typer.Context,
    scope: Annotated[
        str,
        typer.Option(
            '--scope',
            '-s',
            help='Check scope: "user", "repo", or "all" for both.',
        ),
    ] = 'all',
    ide: Annotated[
        str,
        typer.Option(
            '--ide',
            help='IDE to check status for (e.g., "cursor", "claude-code", or "all" for all IDEs). Defaults to cursor.',
        ),
    ] = AIIDEType.CURSOR.value,
    repo_path: Annotated[
        Optional[Path],
        typer.Option(
            '--repo-path',
            help='Repository path for repo-scoped status (defaults to current directory).',
            exists=True,
            file_okay=False,
            dir_okay=True,
            resolve_path=True,
        ),
    ] = None,
) -> None:
    """Show AI guardrails hook installation status.

    Displays the current status of Cycode AI guardrails hooks for the specified IDE.

    Examples:
        cycode ai-guardrails status                # Show both user and repo status
        cycode ai-guardrails status --scope user   # Show only user-level status
        cycode ai-guardrails status --scope repo   # Show only repo-level status
        cycode ai-guardrails status --ide cursor   # Check status for Cursor IDE
        cycode ai-guardrails status --ide all      # Check status for all supported IDEs
    """
    # Validate inputs (status allows 'all' scope)
    validate_scope(scope, allowed_scopes=('user', 'repo', 'all'))
    if repo_path is None:
        repo_path = Path(os.getcwd())
    ide_type = validate_and_parse_ide(ide)

    ides_to_check: list[AIIDEType] = list(AIIDEType) if ide_type is None else [ide_type]

    scopes_to_check = ['user', 'repo'] if scope == 'all' else [scope]

    for current_ide in ides_to_check:
        ide_name = IDE_CONFIGS[current_ide].name
        console.print()
        console.print(f'[bold cyan]═══ {ide_name} ═══[/]')

        for check_scope in scopes_to_check:
            status = get_hooks_status(check_scope, repo_path if check_scope == 'repo' else None, ide=current_ide)

            console.print()
            console.print(f'[bold]{check_scope.upper()} SCOPE[/]')
            console.print(f'Path: {status["hooks_path"]}')

            if not status['file_exists']:
                console.print('[dim]No hooks file found[/]')
                continue

            if status['cycode_installed']:
                console.print('[green]✓ Cycode AI guardrails: INSTALLED[/]')
            else:
                console.print('[yellow]○ Cycode AI guardrails: NOT INSTALLED[/]')

            # Show hook details
            table = Table(show_header=True, header_style='bold')
            table.add_column('Hook Event')
            table.add_column('Cycode Enabled')
            table.add_column('Total Hooks')

            for event, info in status['hooks'].items():
                enabled = '[green]Yes[/]' if info['enabled'] else '[dim]No[/]'
                table.add_row(event, enabled, str(info['total_entries']))

            console.print(table)

    console.print()
