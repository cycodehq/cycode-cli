import typer
from rich.console import Console
from rich.markdown import Markdown

from cycode.cli.models import CliResult
from cycode.cli.printers import ConsolePrinter


def print_remediation(ctx: typer.Context, remediation_markdown: str, is_fix_available: bool) -> None:
    printer = ConsolePrinter(ctx)
    if printer.is_json_printer:
        data = {'remediation': remediation_markdown, 'is_fix_available': is_fix_available}
        printer.print_result(CliResult(success=True, message='Remediation fetched successfully', data=data))
    else:  # text or table
        Console().print(Markdown(remediation_markdown))
