import typer

from cycode.cli.exceptions.custom_exceptions import (
    KNOWN_USER_FRIENDLY_REQUEST_ERRORS,
    AuthProcessError,
)
from cycode.cli.exceptions.handle_errors import handle_errors
from cycode.cli.models import CliError, CliErrors


def handle_auth_exception(ctx: typer.Context, err: Exception) -> None:
    errors: CliErrors = {
        **KNOWN_USER_FRIENDLY_REQUEST_ERRORS,
        AuthProcessError: CliError(
            code='auth_error', message='Authentication failed. Please try again later using the command `cycode auth`'
        ),
    }
    handle_errors(ctx, err, errors)
