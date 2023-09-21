import click

from cycode.cli.commands.report.sbom.sbom_command import sbom_command
from cycode.cli.utils.get_api_client import get_report_cycode_client


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

    return 1
