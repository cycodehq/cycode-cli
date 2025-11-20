import typer

from cycode.cli.utils.sentry import add_breadcrumb


def report_import_command(ctx: typer.Context) -> int:
    """:bar_chart: [bold cyan]Import security reports.[/]

    Example usage:
    * `cycode import sbom`: Import SBOM report
    """
    add_breadcrumb('import')
    return 1
