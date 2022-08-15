import click
import traceback
from cli.auth.auth_manager import AuthManager
from cli.exceptions.custom_exceptions import AuthProcessError, CycodeError
from cyclient import logger


@click.command()
@click.pass_context
def authenticate(context: click.Context):
    """ Authenticates your machine to associate CLI with your cycode account """
    try:
        logger.debug("starting authentication process")
        auth_manager = AuthManager()
        auth_manager.authenticate()
        click.echo("Successfully logged into cycode")
    except Exception as e:
        _handle_exception(context, e)


def _handle_exception(context: click.Context, e: Exception):
    verbose = context.obj["verbose"]
    if verbose:
        click.secho(f'Error: {traceback.format_exc()}', fg='red', nl=False)
    if isinstance(e, AuthProcessError):
        click.secho('Authentication failed. Please try again later using the command `cycode auth`',
                    fg='red', nl=False)
    elif isinstance(e, CycodeError):
        click.secho('Authentication failed. Please try again later using the command `cycode auth`',
                    fg='red', nl=False)
    elif isinstance(e, click.ClickException):
        raise e
    else:
        raise click.ClickException(str(e))
