import click

from cycode.cli.commands.report.sbom.common import create_sbom_report
from cycode.cli.commands.report.sbom.handle_errors import handle_report_exception
from cycode.cli.utils.progress_bar import SbomReportProgressBarSection


@click.command(short_help='Generate SBOM report for provided repository URI in the command.')
@click.argument('uri', nargs=1, type=str, required=True)
@click.pass_context
def sbom_repository_url_command(context: click.Context, uri: str) -> None:
    progress_bar = context.obj['progress_bar']
    progress_bar.start()
    progress_bar.set_section_length(SbomReportProgressBarSection.PREPARE_LOCAL_FILES)

    client = context.obj['client']
    report_parameters = context.obj['report_parameters']
    output_file = context.obj['output_file']
    output_format = report_parameters.output_format

    try:
        sbom_report = client.request_sbom_report(report_parameters, repository_url=uri)
        create_sbom_report(progress_bar, client, sbom_report.id, output_file, output_format)
    except Exception as e:
        progress_bar.stop()
        handle_report_exception(context, e)
