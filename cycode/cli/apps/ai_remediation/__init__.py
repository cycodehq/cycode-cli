import typer

from cycode.cli.apps.ai_remediation.ai_remediation_command import ai_remediation_command

app = typer.Typer()

_ai_remediation_epilog = (
    'Note: AI remediation suggestions are generated automatically and should be reviewed before applying.'
)

app.command(
    name='ai-remediation',
    short_help='Get AI remediation (INTERNAL).',
    epilog=_ai_remediation_epilog,
    hidden=True,
    no_args_is_help=True,
)(ai_remediation_command)

# backward compatibility
app.command(hidden=True, name='ai_remediation')(ai_remediation_command)
