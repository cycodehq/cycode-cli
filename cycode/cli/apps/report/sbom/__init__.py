import typer

from cycode.cli.apps.report.sbom.path.path_command import path_command
from cycode.cli.apps.report.sbom.repository_url.repository_url_command import repository_url_command
from cycode.cli.apps.report.sbom.sbom_command import sbom_command

app = typer.Typer(name='sbom')
app.callback(short_help='Generate SBOM report for remote repository by url or local directory by path.')(sbom_command)
app.command(name='path', short_help='Generate SBOM report for provided path in the command.')(path_command)
app.command(name='repository-url', short_help='Generate SBOM report for provided repository URI in the command.')(
    repository_url_command
)

# backward compatibility
app.command(hidden=True, name='repository_url')(repository_url_command)
