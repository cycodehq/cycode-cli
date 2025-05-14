from typing import Optional

import click
import typer

from cycode.cli.models import CliError, CliErrors
from cycode.cli.utils.sentry import capture_exception


def handle_errors(
    ctx: typer.Context, err: BaseException, cli_errors: CliErrors, *, return_exception: bool = False
) -> Optional['CliError']:
    printer = ctx.obj.get('console_printer')
    printer.print_exception(err)

    if type(err) in cli_errors:
        error = cli_errors[type(err)].enrich(additional_message=str(err))

        if error.soft_fail is True:
            ctx.obj['soft_fail'] = True

        if return_exception:
            return error

        printer.print_error(error)
        return None

    if isinstance(err, click.ClickException):
        raise err

    capture_exception(err)

    unknown_error = CliError(code='unknown_error', message=str(err))
    if return_exception:
        return unknown_error

    printer.print_error(unknown_error)
    raise typer.Exit(1)
