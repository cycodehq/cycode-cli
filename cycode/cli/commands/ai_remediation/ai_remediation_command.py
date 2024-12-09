import os

import click
from patch_ng import fromstring
from rich.console import Console
from rich.markdown import Markdown

from cycode.cli.exceptions.handle_ai_remediation_errors import handle_ai_remediation_exception
from cycode.cli.models import CliResult
from cycode.cli.printers import ConsolePrinter
from cycode.cli.utils.get_api_client import get_scan_cycode_client


def _echo_remediation(context: click.Context, remediation_markdown: str, is_fix_available: bool) -> None:
    printer = ConsolePrinter(context)
    if printer.is_json_printer:
        data = {'remediation': remediation_markdown, 'is_fix_available': is_fix_available}
        printer.print_result(CliResult(success=True, message='Remediation fetched successfully', data=data))
    else:  # text or table
        Console().print(Markdown(remediation_markdown))


def _apply_fix(context: click.Context, diff: str, is_fix_available: bool) -> None:
    printer = ConsolePrinter(context)
    if not is_fix_available:
        printer.print_result(CliResult(success=False, message='Fix is not available for this violation'))
        return

    patch = fromstring(diff.encode('UTF-8'))
    if patch is False:
        printer.print_result(CliResult(success=False, message='Failed to parse fix diff'))
        return

    is_fix_applied = patch.apply(root=os.getcwd(), strip=0)
    if is_fix_applied:
        printer.print_result(CliResult(success=True, message='Fix applied successfully'))
    else:
        printer.print_result(CliResult(success=False, message='Failed to apply fix'))


@click.command(short_help='Get AI remediation (INTERNAL).', hidden=True)
@click.argument('detection_id', nargs=1, type=click.UUID, required=True)
@click.option(
    '--fix',
    is_flag=True,
    default=False,
    help='Apply fixes to resolve violations. Fix is not available for all violations.',
    type=click.BOOL,
    required=False,
)
@click.pass_context
def ai_remediation_command(context: click.Context, detection_id: str, fix: bool) -> None:
    client = get_scan_cycode_client()

    try:
        remediation_markdown = client.get_ai_remediation(detection_id)
        fix_diff = client.get_ai_remediation(detection_id, fix=True)
        is_fix_available = bool(fix_diff)  # exclude empty string, None, etc.

        if fix:
            _apply_fix(context, fix_diff, is_fix_available)
        else:
            _echo_remediation(context, remediation_markdown, is_fix_available)
    except Exception as err:
        handle_ai_remediation_exception(context, err)

    context.exit()
