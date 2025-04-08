import typer

from cycode.cli.apps.ai_remediation.ai_remediation_command import ai_remediation_command

app = typer.Typer()
app.command(name='ai-remediation', short_help='Get AI remediation (INTERNAL).', hidden=True)(ai_remediation_command)

# backward compatibility
app.command(hidden=True, name='ai_remediation')(ai_remediation_command)
