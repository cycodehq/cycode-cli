import os

import typer
from patch_ng import fromstring

from cycode.cli.models import CliResult


def apply_fix(ctx: typer.Context, diff: str, is_fix_available: bool) -> None:
    printer = ctx.obj.get('console_printer')
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
