"""Install command for AI guardrails hooks."""

from pathlib import Path
from typing import Annotated, Optional

import typer

from cycode.cli.apps.ai_guardrails.command_utils import console, resolve_repo_path, validate_scope
from cycode.cli.apps.ai_guardrails.consts import GuardrailsMode
from cycode.cli.apps.ai_guardrails.hooks_manager import create_policy_file, install_hooks
from cycode.cli.apps.ai_guardrails.ides import DEFAULT_IDE_NAME, IDES, resolve_ides


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
            help=f'IDE to install hooks for ({", ".join(IDES)}, or "all" for every supported IDE).',
        ),
    ] = DEFAULT_IDE_NAME,
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
    mode: Annotated[
        GuardrailsMode,
        typer.Option(
            '--mode',
            '-m',
            help='[Deprecated] Enforcement mode is platform-managed; configure guardrails in the Cycode platform.',
        ),
    ] = GuardrailsMode.REPORT,
) -> None:
    """Install AI guardrails hooks for supported IDEs.

    Configures the specified IDE to use Cycode for scanning prompts, file reads,
    and MCP tool calls for secrets before they reach the AI model.

    Examples:
        cycode ai-guardrails install                    # Install in report mode (default)
        cycode ai-guardrails install --mode block       # Install in block mode
        cycode ai-guardrails install --scope repo       # Install for current repo only
        cycode ai-guardrails install --ide claude-code  # Install for a specific IDE
        cycode ai-guardrails install --ide all          # Install for every supported IDE
    """
    validate_scope(scope)
    repo_path = resolve_repo_path(scope, repo_path)
    ides_to_install = resolve_ides(ide)

    results: list[tuple[str, bool, str]] = []
    for current_ide in ides_to_install:
        success, message = install_hooks(current_ide, scope, repo_path)
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

    if mode == GuardrailsMode.BLOCK:
        console.print(
            '[yellow]--mode is deprecated:[/] enforcement mode is platform-managed; '
            'configure guardrails in the Cycode platform.'
        )

    if any_success:
        _install_policy(scope, repo_path)
        _print_next_steps(results)

    if not all_success:
        raise typer.Exit(1)


def _install_policy(scope: str, repo_path: Optional[Path]) -> None:
    policy_success, policy_message = create_policy_file(scope, repo_path)
    if policy_success:
        console.print(f'[green]✓[/] {policy_message}')
    else:
        console.print(f'[red]✗[/] {policy_message}', style='bold red')


def _print_next_steps(results: list[tuple[str, bool, str]]) -> None:
    console.print()
    console.print('[bold]Next steps:[/]')
    successful_ides = [name for name, success, _ in results if success]
    ide_list = ', '.join(successful_ides)
    console.print(f'1. Restart {ide_list} to activate the hooks')
    console.print('2. Configure guardrail enforcement in the Cycode platform')
    console.print()
    console.print('[dim]The hooks will scan prompts, file reads, and MCP tool calls for secrets.[/]')
