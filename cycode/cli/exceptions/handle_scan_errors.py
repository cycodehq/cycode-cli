from typing import Optional

import click

from cycode.cli.exceptions import custom_exceptions
from cycode.cli.exceptions.custom_exceptions import KNOWN_USER_FRIENDLY_REQUEST_ERRORS
from cycode.cli.models import CliError, CliErrors
from cycode.cli.printers import ConsolePrinter
from cycode.cli.sentry import capture_exception
from cycode.cli.utils.git_proxy import git_proxy


def handle_scan_exception(
    context: click.Context, e: Exception, *, return_exception: bool = False
) -> Optional[CliError]:
    context.obj['did_fail'] = True

    ConsolePrinter(context).print_exception(e)

    errors: CliErrors = {
        **KNOWN_USER_FRIENDLY_REQUEST_ERRORS,
        custom_exceptions.ScanAsyncError: CliError(
            soft_fail=True,
            code='scan_error',
            message='Cycode was unable to complete this scan. '
            'Please try again by executing the `cycode scan` command',
        ),
        custom_exceptions.ZipTooLargeError: CliError(
            soft_fail=True,
            code='zip_too_large_error',
            message='The path you attempted to scan exceeds the current maximum scanning size cap (10MB). '
            'Please try ignoring irrelevant paths using the `cycode ignore --by-path` command '
            'and execute the scan again',
        ),
        custom_exceptions.TfplanKeyError: CliError(
            soft_fail=True,
            code='key_error',
            message=f'\n{e!s}\n'
            'A crucial field is missing in your terraform plan file. '
            'Please make sure that your file is well formed '
            'and execute the scan again',
        ),
        git_proxy.get_invalid_git_repository_error(): CliError(
            soft_fail=False,
            code='invalid_git_error',
            message='The path you supplied does not correlate to a git repository. '
            'If you still wish to scan this path, use: `cycode scan path <path>`',
        ),
    }

    if type(e) in errors:
        error = errors[type(e)]

        if error.soft_fail is True:
            context.obj['soft_fail'] = True

        if return_exception:
            return error

        ConsolePrinter(context).print_error(error)
        return None

    if isinstance(e, click.ClickException):
        raise e

    capture_exception(e)

    unknown_error = CliError(code='unknown_error', message=str(e))
    if return_exception:
        return unknown_error

    ConsolePrinter(context).print_error(unknown_error)
    exit(1)
