import click
from cli.auth.auth_manager import AuthManager
from cyclient import logger


@click.command()
def authenticate():
    """ Initial command to authenticate your CLI - TODO better text """
    logger.debug("starting authentication process")
    auth_manager = AuthManager()
    auth_manager.authenticate()
    click.echo("success")
