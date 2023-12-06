import traceback
from typing import Optional

import click
from git import InvalidGitRepositoryError

from cycode.cli.exceptions import custom_exceptions
from cycode.cli.models import CliError, CliErrors
from cycode.cli.printers import ConsolePrinter


def handle_scan_exception(
    context: click.Context, e: Exception, *, return_exception: bool = False
) -> Optional[CliError]:
    context.obj['did_fail'] = True

    if context.obj['verbose']:
        click.secho(f'Error: {traceback.format_exc()}', fg='red')

    errors: CliErrors = {
        custom_exceptions.NetworkError: CliError(
            soft_fail=True,
            code='cycode_error',
            message='Cycode was unable to complete this scan. '
            'Please try again by executing the `cycode scan` command',
        ),
        custom_exceptions.ScanAsyncError: CliError(
            soft_fail=True,
            code='scan_error',
            message='Cycode was unable to complete this scan. '
            'Please try again by executing the `cycode scan` command',
        ),
        custom_exceptions.HttpUnauthorizedError: CliError(
            soft_fail=True,
            code='auth_error',
            message='Unable to authenticate to Cycode, your token is either invalid or has expired. '
            'Please re-generate your token and reconfigure it by running the `cycode configure` command',
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
        InvalidGitRepositoryError: CliError(
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

    if return_exception:
        return CliError(code='unknown_error', message=str(e))

    if isinstance(e, click.ClickException):
        raise e

    raise click.ClickException(str(e))
