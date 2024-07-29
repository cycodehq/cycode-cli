from typing import Optional

import click

from cycode.cli.exceptions import custom_exceptions
from cycode.cli.exceptions.custom_exceptions import KNOWN_USER_FRIENDLY_REQUEST_ERRORS
from cycode.cli.models import CliError, CliErrors
from cycode.cli.printers import ConsolePrinter
from cycode.cli.sentry import capture_exception


def handle_report_exception(context: click.Context, err: Exception) -> Optional[CliError]:
    ConsolePrinter(context).print_exception()

    errors: CliErrors = {
        **KNOWN_USER_FRIENDLY_REQUEST_ERRORS,
        custom_exceptions.ScanAsyncError: CliError(
            code='report_error',
            message='Cycode was unable to complete this report. '
            'Please try again by executing the `cycode report` command',
        ),
        custom_exceptions.ReportAsyncError: CliError(
            code='report_error',
            message='Cycode was unable to complete this report. '
            'Please try again by executing the `cycode report` command',
        ),
    }

    if type(err) in errors:
        error = errors[type(err)]

        ConsolePrinter(context).print_error(error)
        return None

    if isinstance(err, click.ClickException):
        raise err

    capture_exception(err)

    raise click.ClickException(str(err))
