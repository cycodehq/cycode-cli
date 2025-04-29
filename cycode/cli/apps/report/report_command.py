import typer

from cycode.cli.utils.progress_bar import SBOM_REPORT_PROGRESS_BAR_SECTIONS, get_progress_bar
from cycode.cli.utils.sentry import add_breadcrumb


def report_command(ctx: typer.Context) -> int:
    """:bar_chart: [bold cyan]Generate security reports.[/]

    Example usage:
    * `cycode report sbom`: Generate SBOM report
    """
    add_breadcrumb('report')
    ctx.obj['progress_bar'] = get_progress_bar(hidden=False, sections=SBOM_REPORT_PROGRESS_BAR_SECTIONS)
    return 1
