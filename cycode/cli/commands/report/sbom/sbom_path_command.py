import click

from cycode.cli import consts
from cycode.cli.commands.report.sbom.common import create_sbom_report
from cycode.cli.files_collector.path_documents import get_relevant_document
from cycode.cli.files_collector.sca.sca_code_scanner import perform_pre_scan_documents_actions
from cycode.cli.files_collector.zip_documents import zip_documents


@click.command(short_help='Generate SBOM report for provided path in the command.')
@click.argument('path', nargs=1, type=click.Path(exists=True, resolve_path=True), required=True)
@click.pass_context
def sbom_path_command(context: click.Context, path: str) -> None:
    client = context.obj['client']
    report_parameters = context.obj['report_parameters']
    output_file = context.obj['output_file']

    # TODO(MarshalX): add support of progress bar somehow?
    progress_bar = context.obj['progress_bar']
    progress_bar.start()

    documents = get_relevant_document(progress_bar, consts.SCA_SCAN_TYPE, path)
    # TODO(MarshalX): refactoring more. Combine into one function.
    perform_pre_scan_documents_actions(context, consts.SCA_SCAN_TYPE, documents)

    zipped_documents = zip_documents(consts.SCA_SCAN_TYPE, documents)
    sbom_report = client.request_sbom_report(report_parameters, zip_file=zipped_documents)

    create_sbom_report(client, sbom_report.id, output_file)
