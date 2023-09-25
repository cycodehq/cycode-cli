import click

from cycode.cli.commands.report.sbom.sbom_command import sbom_command
from cycode.cli.utils.get_api_client import get_report_cycode_client
from cycode.cli.utils.progress_bar import SBOM_REPORT_PROGRESS_BAR_SECTIONS, get_progress_bar


@click.group(
    commands={
        'sbom': sbom_command,
    },
    short_help='Generate report. You`ll need to specify which report type to perform.',
)
@click.pass_context
def report_command(
    context: click.Context,
) -> int:
    """Generate report."""

    context.obj['client'] = get_report_cycode_client(hide_response_log=False)  # TODO disable log
    context.obj['progress_bar'] = get_progress_bar(hidden=False, sections=SBOM_REPORT_PROGRESS_BAR_SECTIONS)

    return 1
