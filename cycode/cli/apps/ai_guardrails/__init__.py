import typer

from cycode.cli.apps.ai_guardrails.install_command import install_command
from cycode.cli.apps.ai_guardrails.scan.scan_command import scan_command
from cycode.cli.apps.ai_guardrails.status_command import status_command
from cycode.cli.apps.ai_guardrails.uninstall_command import uninstall_command

app = typer.Typer(name='ai-guardrails', no_args_is_help=True, hidden=True)

app.command(hidden=True, name='install', short_help='Install AI guardrails hooks for supported IDEs.')(install_command)
app.command(hidden=True, name='uninstall', short_help='Remove AI guardrails hooks from supported IDEs.')(
    uninstall_command
)
app.command(hidden=True, name='status', short_help='Show AI guardrails hook installation status.')(status_command)
app.command(
    hidden=True,
    name='scan',
    short_help='Scan content from AI IDE hooks for secrets (reads JSON from stdin).',
)(scan_command)
