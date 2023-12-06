import traceback
from typing import Optional

import click

from cycode.cli.exceptions import custom_exceptions
from cycode.cli.models import CliError, CliErrors
from cycode.cli.printers import ConsolePrinter


def handle_report_exception(context: click.Context, err: Exception) -> Optional[CliError]:
    if context.obj['verbose']:
        click.secho(f'Error: {traceback.format_exc()}', fg='red')

    errors: CliErrors = {
        custom_exceptions.NetworkError: CliError(
            code='cycode_error',
            message='Cycode was unable to complete this report. '
            'Please try again by executing the `cycode report` command',
        ),
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
        custom_exceptions.HttpUnauthorizedError: CliError(
            code='auth_error',
            message='Unable to authenticate to Cycode, your token is either invalid or has expired. '
            'Please re-generate your token and reconfigure it by running the `cycode configure` command',
        ),
    }

    if type(err) in errors:
        error = errors[type(err)]

        ConsolePrinter(context).print_error(error)
        return None

    if isinstance(err, click.ClickException):
        raise err

    raise click.ClickException(str(err))
