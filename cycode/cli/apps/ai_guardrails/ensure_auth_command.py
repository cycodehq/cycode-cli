import typer

from cycode.cli.apps.auth.auth_common import get_authorization_info
from cycode.cli.apps.auth.auth_manager import AuthManager
from cycode.cli.exceptions.handle_auth_errors import handle_auth_exception
from cycode.cli.logger import logger


def ensure_auth_command(ctx: typer.Context) -> None:
    """Ensure the user is authenticated, triggering authentication if needed."""
    auth_info = get_authorization_info(ctx)
    if auth_info is not None:
        logger.debug('Already authenticated')
        return

    logger.debug('Not authenticated, starting authentication')
    try:
        auth_manager = AuthManager()
        auth_manager.authenticate()
    except Exception as err:
        handle_auth_exception(ctx, err)
