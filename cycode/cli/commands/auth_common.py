from typing import NamedTuple, Optional

import click

from cycode.cli.exceptions.custom_exceptions import HttpUnauthorizedError, RequestHttpError
from cycode.cli.printers import ConsolePrinter
from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cli.utils.jwt_utils import get_user_and_tenant_ids_from_access_token
from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient


class AuthInfo(NamedTuple):
    user_id: str
    tenant_id: str


def get_authorization_info(context: Optional[click.Context] = None) -> Optional[AuthInfo]:
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
        if context:
            ConsolePrinter(context).print_exception()

        return None
