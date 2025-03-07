import typer

from cycode.cli.apps.report import sbom
from cycode.cli.apps.report.report_command import report_command

app = typer.Typer(name='report')
app.callback(short_help='Generate report. You`ll need to specify which report type to perform.')(report_command)
app.add_typer(sbom.app)
