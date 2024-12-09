import click

from cycode.cli.exceptions.common import handle_errors
from cycode.cli.exceptions.custom_exceptions import KNOWN_USER_FRIENDLY_REQUEST_ERRORS, RequestHttpError
from cycode.cli.models import CliError, CliErrors


class AiRemediationNotFoundError(Exception): ...


def handle_ai_remediation_exception(context: click.Context, err: Exception) -> None:
    if isinstance(err, RequestHttpError) and err.status_code == 404:
        err = AiRemediationNotFoundError()

    errors: CliErrors = {
        **KNOWN_USER_FRIENDLY_REQUEST_ERRORS,
        AiRemediationNotFoundError: CliError(
            code='ai_remediation_not_found',
            message='The AI remediation was not found. Please try different detection ID',
        ),
    }
    handle_errors(context, err, errors)
