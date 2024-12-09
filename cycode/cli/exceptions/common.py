from typing import Optional

import click

from cycode.cli.models import CliError, CliErrors
from cycode.cli.printers import ConsolePrinter
from cycode.cli.sentry import capture_exception


def handle_errors(
    context: click.Context, err: BaseException, cli_errors: CliErrors, *, return_exception: bool = False
) -> Optional['CliError']:
    ConsolePrinter(context).print_exception(err)

    if type(err) in cli_errors:
        error = cli_errors[type(err)]

        if error.soft_fail is True:
            context.obj['soft_fail'] = True

        if return_exception:
            return error

        ConsolePrinter(context).print_error(error)
        return None

    if isinstance(err, click.ClickException):
        raise err

    capture_exception(err)

    unknown_error = CliError(code='unknown_error', message=str(err))
    if return_exception:
        return unknown_error

    ConsolePrinter(context).print_error(unknown_error)
    exit(1)
