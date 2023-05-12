import json

import click
import traceback

from cycode.cli.auth.auth_manager import AuthManager
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cli.exceptions.custom_exceptions import AuthProcessError, NetworkError, HttpUnauthorizedError
from cycode.cyclient import logger
from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient


@click.group(invoke_without_command=True)
@click.pass_context
def authenticate(context: click.Context):
    """ Authenticates your machine to associate CLI with your cycode account """
    if context.invoked_subcommand is not None:
        # if it is a subcommand do nothing
        return

    try:
        logger.debug("starting authentication process")
        auth_manager = AuthManager()
        auth_manager.authenticate()
        click.echo("Successfully logged into cycode")
    except Exception as e:
        _handle_exception(context, e)


@authenticate.command(name='check')
@click.pass_context
def authorization_check(context: click.Context):
    """ Check your machine associating CLI with your cycode account """
    passed_auth_check_args = {'context': context, 'content': {
        'success': True,
        'message': 'You are authorized'
    }, 'color': 'green'}
    failed_auth_check_args = {'context': context, 'content': {
        'success': False,
        'message': 'You are not authorized'
    }, 'color': 'red'}

    client_id, client_secret = CredentialsManager().get_credentials()
    if not client_id or not client_secret:
        return _print_result(**failed_auth_check_args)

    try:
        # TODO(MarshalX): This property performs HTTP request to refresh the token. This must be the method.
        if CycodeTokenBasedClient(client_id, client_secret).api_token:
            return _print_result(**passed_auth_check_args)
    except (NetworkError, HttpUnauthorizedError):
        if context.obj['verbose']:
            click.secho(f'Error: {traceback.format_exc()}', fg='red', nl=False)

        return _print_result(**failed_auth_check_args)


def _print_result(context: click.Context, content: dict, color: str) -> None:
    # the current impl of printers supports only results of scans
    if context.obj['output'] == 'text':
        return click.secho(content['message'], fg=color)

    return click.echo(json.dumps({'result': content['success'], 'message': content['message']}))


def _handle_exception(context: click.Context, e: Exception):
    verbose = context.obj["verbose"]
    if verbose:
        click.secho(f'Error: {traceback.format_exc()}', fg='red', nl=False)
    if isinstance(e, AuthProcessError):
        click.secho('Authentication failed. Please try again later using the command `cycode auth`',
                    fg='red', nl=False)
    elif isinstance(e, NetworkError):
        click.secho('Authentication failed. Please try again later using the command `cycode auth`',
                    fg='red', nl=False)
    elif isinstance(e, click.ClickException):
        raise e
    else:
        raise click.ClickException(str(e))
