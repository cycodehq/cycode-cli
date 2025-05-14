from typing import TYPE_CHECKING, Optional

from cycode.cli.apps.auth.models import AuthInfo
from cycode.cli.exceptions.custom_exceptions import HttpUnauthorizedError, RequestHttpError
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cli.utils.jwt_utils import get_user_and_tenant_ids_from_access_token
from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient

if TYPE_CHECKING:
    from typer import Context


def get_authorization_info(ctx: 'Context') -> Optional[AuthInfo]:
    printer = ctx.obj.get('console_printer')

    client_id, client_secret = ctx.obj.get('client_id'), ctx.obj.get('client_secret')
    if not client_id or not client_secret:
        client_id, client_secret = CredentialsManager().get_credentials()

    if not client_id or not client_secret:
        return None

    try:
        access_token = CycodeTokenBasedClient(client_id, client_secret).get_access_token()
        if not access_token:
            return None

        user_id, tenant_id = get_user_and_tenant_ids_from_access_token(access_token)
        return AuthInfo(user_id=user_id, tenant_id=tenant_id)
    except (RequestHttpError, HttpUnauthorizedError):
        if ctx:
            printer.print_exception()

        return None
