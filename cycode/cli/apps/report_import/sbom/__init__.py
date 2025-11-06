import typer

from cycode.cli.apps.report_import.sbom.sbom_command import sbom_command

app = typer.Typer(name='sbom')
app.command(name='path', short_help='Import SBOM report from a local path.')(sbom_command)
