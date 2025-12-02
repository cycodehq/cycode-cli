from typing import TYPE_CHECKING, Optional, Union

import click

from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cyclient.client_creator import create_import_sbom_client, create_report_client, create_scan_client

if TYPE_CHECKING:
    import typer

    from cycode.cyclient.import_sbom_client import ImportSbomClient
    from cycode.cyclient.report_client import ReportClient
    from cycode.cyclient.scan_client import ScanClient


def _get_cycode_client(
    create_client_func: callable,
    client_id: Optional[str],
    client_secret: Optional[str],
    hide_response_log: bool,
    id_token: Optional[str] = None,
) -> Union['ScanClient', 'ReportClient']:
    if client_id and id_token:
        return create_client_func(client_id, None, hide_response_log, id_token)

    if not client_id or not id_token:
        oidc_client_id, oidc_id_token = _get_configured_oidc_credentials()
        if oidc_client_id and oidc_id_token:
            return create_client_func(oidc_client_id, None, hide_response_log, oidc_id_token)
        if oidc_id_token and not oidc_client_id:
            raise click.ClickException('Cycode client id needed for OIDC authentication.')

    if not client_id or not client_secret:
        client_id, client_secret = _get_configured_credentials()
        if not client_id:
            raise click.ClickException('Cycode client id needed.')
        if not client_secret:
            raise click.ClickException('Cycode client secret is needed.')

    return create_client_func(client_id, client_secret, hide_response_log, None)


def get_scan_cycode_client(ctx: 'typer.Context') -> 'ScanClient':
    client_id = ctx.obj.get('client_id')
    client_secret = ctx.obj.get('client_secret')
    id_token = ctx.obj.get('id_token')
    hide_response_log = not ctx.obj.get('show_secret', False)
    return _get_cycode_client(create_scan_client, client_id, client_secret, hide_response_log, id_token)


def get_report_cycode_client(ctx: 'typer.Context', hide_response_log: bool = True) -> 'ReportClient':
    client_id = ctx.obj.get('client_id')
    client_secret = ctx.obj.get('client_secret')
    id_token = ctx.obj.get('id_token')
    return _get_cycode_client(create_report_client, client_id, client_secret, hide_response_log, id_token)


def get_import_sbom_cycode_client(ctx: 'typer.Context', hide_response_log: bool = True) -> 'ImportSbomClient':
    client_id = ctx.obj.get('client_id')
    client_secret = ctx.obj.get('client_secret')
    id_token = ctx.obj.get('id_token')
    return _get_cycode_client(create_import_sbom_client, client_id, client_secret, hide_response_log, id_token)


def _get_configured_credentials() -> tuple[str, str]:
    credentials_manager = CredentialsManager()
    return credentials_manager.get_credentials()


def _get_configured_oidc_credentials() -> tuple[Optional[str], Optional[str]]:
    credentials_manager = CredentialsManager()
    return credentials_manager.get_oidc_credentials()
