import click

from cycode.cli.commands.report.sbom.common import create_sbom_report


@click.command(short_help='Generate SBOM report for provided repository URI in the command.')
@click.argument('uri', nargs=1, type=str, required=True)
@click.pass_context
def sbom_repository_url_command(context: click.Context, uri: str) -> None:
    client = context.obj['client']
    report_parameters = context.obj['report_parameters']
    output_file = context.obj['output_file']
    # TODO(MarshalX): add support of progress bar somehow?
    sbom_report = client.request_sbom_report(report_parameters, repository_url=uri)
    create_sbom_report(client, sbom_report.id, output_file)
