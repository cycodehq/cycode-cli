import typer

from cycode.cli.exceptions import custom_exceptions
from cycode.cli.exceptions.custom_exceptions import KNOWN_USER_FRIENDLY_REQUEST_ERRORS
from cycode.cli.exceptions.handle_errors import handle_errors
from cycode.cli.models import CliError, CliErrors


def handle_report_exception(ctx: typer.Context, err: Exception) -> None:
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
    handle_errors(ctx, err, errors)
