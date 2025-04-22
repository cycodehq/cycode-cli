import typer
from rich.markdown import Markdown

from cycode.cli.console import console
from cycode.cli.models import CliResult


def print_remediation(ctx: typer.Context, remediation_markdown: str, is_fix_available: bool) -> None:
    printer = ctx.obj.get('console_printer')
    if printer.is_json_printer:
        data = {'remediation': remediation_markdown, 'is_fix_available': is_fix_available}
        printer.print_result(CliResult(success=True, message='Remediation fetched successfully', data=data))
    else:  # text or table
        console.print(Markdown(remediation_markdown))
