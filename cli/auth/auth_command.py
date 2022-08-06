import click
import traceback
from cli.auth.auth_manager import AuthManager
from cli.exceptions.custom_exceptions import AuthProcessError, CycodeError
from cyclient import logger


@click.command()
@click.pass_context
def authenticate(context: click.Context):
    """ Initial command to authenticate your CLI - TODO better text """
    try:
        logger.debug("starting authentication process")
        auth_manager = AuthManager()
        auth_manager.authenticate()
        click.echo("success TODO TEXT")
    except Exception as e:
        _handle_exception(context, e)


def _handle_exception(context: click.Context, e: Exception):
    verbose = context.obj["verbose"]
    if verbose:
        click.secho(f'Error: {traceback.format_exc()}', fg='red', nl=False)
    if isinstance(e, AuthProcessError):
        click.secho('Authentication process has failed. Please try again by executing the `cycode auth` command',
                    fg='red', nl=False)
    elif isinstance(e, CycodeError):
        click.secho('TBD message. Please try again by executing the `cycode auth` command',
                    fg='red', nl=False)
    elif isinstance(e, click.ClickException):
        raise e
    else:
        raise click.ClickException(str(e))
