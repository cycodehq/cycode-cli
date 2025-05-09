import typer

from cycode.cli.apps.status.get_cli_status import get_cli_status
from cycode.cli.cli_types import OutputTypeOption
from cycode.cli.console import console


def status_command(ctx: typer.Context) -> None:
    """:information_source: [bold cyan]Show Cycode CLI status and configuration.[/]

    This command displays the current status and configuration of the Cycode CLI, including:
    * Authentication status: Whether you're logged in
    * Version information: Current CLI version
    * Configuration: Current API endpoints and settings
    * System information: Operating system and environment details

    Output formats:
    * Text: Human-readable format (default)
    * JSON: Machine-readable format

    Example usage:
    * `cycode status`: Show status in text format
    * `cycode -o json status`: Show status in JSON format
    """
    output = ctx.obj['output']

    cli_status = get_cli_status(ctx)
    if output == OutputTypeOption.JSON:
        console.print_json(cli_status.as_json())
    else:
        console.print(cli_status.as_text())
