import click

from cycode.cli.commands.report.sbom.sbom_path_command import sbom_path_command
from cycode.cli.commands.report.sbom.sbom_repository_url_command import sbom_repository_url_command
from cycode.cli.config import config
from cycode.cyclient.report_client import ReportParameters


@click.group(
    commands={
        'path': sbom_path_command,
        'repository_url': sbom_repository_url_command,
    },
    short_help='Generate SBOM report. You`ll need to specify which report type to perform: path/repository_url.',
)
@click.option(
    '--format',
    '-f',
    help='SBOM format.',
    type=click.Choice(config['scans']['supported_sbom_formats']),
    required=True,
)
@click.option(
    '--output-format',
    '-o',
    default='json',
    help='Specify the output file format (the default is json).',
    type=click.Choice(['csv', 'json']),
    required=False,
)
@click.option(
    '--output-file',
    help='Output file.',
    default=None,
    type=click.Path(resolve_path=True),
    required=False,
)
@click.option(
    '--include-vulnerabilities',
    is_flag=True,
    default=False,
    help='Include vulnerabilities.',
    type=bool,
    required=False,
)
@click.option(
    '--include-dev-dependencies',
    is_flag=True,
    default=False,
    help='Include dev dependencies.',
    type=bool,
    required=False,
)
@click.pass_context
def sbom_command(
    context: click.Context,
    format: str,
    output_format: str,
    output_file: str,
    include_vulnerabilities: bool,
    include_dev_dependencies: bool,
) -> int:
    """Generate SBOM report."""
    sbom_format_parts = format.split('-')
    if len(sbom_format_parts) != 2:
        raise click.ClickException('Invalid SBOM format.')

    sbom_format, sbom_format_version = sbom_format_parts

    report_parameters = ReportParameters(
        entity_type='SbomCli',
        sbom_report_type=sbom_format,
        sbom_version=sbom_format_version,
        output_format=output_format,
        include_vulnerabilities=include_vulnerabilities,
        include_dev_dependencies=include_dev_dependencies,
    )
    context.obj['report_parameters'] = report_parameters
    context.obj['output_file'] = output_file

    return 1
