from typing import Optional

import typer

from cycode.cli.exceptions import custom_exceptions
from cycode.cli.exceptions.custom_exceptions import KNOWN_USER_FRIENDLY_REQUEST_ERRORS
from cycode.cli.exceptions.handle_errors import handle_errors
from cycode.cli.models import CliError, CliErrors
from cycode.cli.utils.git_proxy import git_proxy


def handle_scan_exception(ctx: typer.Context, err: Exception, *, return_exception: bool = False) -> Optional[CliError]:
    ctx.obj['did_fail'] = True

    errors: CliErrors = {
        **KNOWN_USER_FRIENDLY_REQUEST_ERRORS,
        custom_exceptions.ScanAsyncError: CliError(
            soft_fail=True,
            code='scan_error',
            message='Cycode was unable to complete this scan. Please try again by executing the `cycode scan` command',
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
            message=f'\n{err!s}\n'
            'A crucial field is missing in your terraform plan file. '
            'Please make sure that your file is well formed '
            'and execute the scan again',
        ),
        git_proxy.get_invalid_git_repository_error(): CliError(
            soft_fail=False,
            code='invalid_git_error',
            message='The path you supplied does not correlate to a Git repository. '
            'If you still wish to scan this path, use: `cycode scan path <path>`',
        ),
    }

    return handle_errors(ctx, err, errors, return_exception=return_exception)
