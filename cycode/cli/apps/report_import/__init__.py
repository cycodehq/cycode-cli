import typer

from cycode.cli.apps.report_import.report_import_command import report_import_command
from cycode.cli.apps.report_import.sbom import sbom_command

app = typer.Typer(name='import', no_args_is_help=True)
app.callback(short_help='Import report. You`ll need to specify which report type to import.')(report_import_command)
app.command(name='sbom', short_help='Import SBOM report from a local path.')(sbom_command)
