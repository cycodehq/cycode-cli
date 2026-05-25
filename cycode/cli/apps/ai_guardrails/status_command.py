"""Status command for AI guardrails hooks."""

import os
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.table import Table

from cycode.cli.apps.ai_guardrails.command_utils import console, validate_scope
from cycode.cli.apps.ai_guardrails.hooks_manager import get_hooks_status
from cycode.cli.apps.ai_guardrails.ides import DEFAULT_IDE_NAME, IDES, resolve_ides


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
            help=f'IDE to check status for ({", ".join(IDES)}, or "all").',
        ),
    ] = DEFAULT_IDE_NAME,
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

    Examples:
        cycode ai-guardrails status                # Show both user and repo status
        cycode ai-guardrails status --scope user   # Show only user-level status
        cycode ai-guardrails status --scope repo   # Show only repo-level status
        cycode ai-guardrails status --ide claude-code
        cycode ai-guardrails status --ide all      # Check every supported IDE
    """
    validate_scope(scope, allowed_scopes=('user', 'repo', 'all'))
    if repo_path is None:
        repo_path = Path(os.getcwd())
    ides_to_check = resolve_ides(ide)

    scopes_to_check = ['user', 'repo'] if scope == 'all' else [scope]

    for current_ide in ides_to_check:
        console.print()
        console.print(f'[bold cyan]═══ {current_ide.display_name} ═══[/]')

        for check_scope in scopes_to_check:
            status = get_hooks_status(
                current_ide,
                check_scope,
                repo_path if check_scope == 'repo' else None,
            )

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

            table = Table(show_header=True, header_style='bold')
            table.add_column('Hook Event')
            table.add_column('Cycode Enabled')
            table.add_column('Total Hooks')

            for event, info in status['hooks'].items():
                enabled = '[green]Yes[/]' if info['enabled'] else '[dim]No[/]'
                table.add_row(event, enabled, str(info['total_entries']))

            console.print(table)

    console.print()
