from typing import TYPE_CHECKING, Optional, Union

import click

from cycode.cli.user_settings.credentials_manager import CredentialsManager
from cycode.cyclient.client_creator import create_report_client, create_scan_client

if TYPE_CHECKING:
    import typer

    from cycode.cyclient.report_client import ReportClient
    from cycode.cyclient.scan_client import ScanClient


def _get_cycode_client(
    create_client_func: callable, client_id: Optional[str], client_secret: Optional[str], hide_response_log: bool
) -> Union['ScanClient', 'ReportClient']:
    if not client_id or not client_secret:
        client_id, client_secret = _get_configured_credentials()
        if not client_id:
            raise click.ClickException('Cycode client id needed.')
        if not client_secret:
            raise click.ClickException('Cycode client secret is needed.')

    return create_client_func(client_id, client_secret, hide_response_log)


def get_scan_cycode_client(ctx: 'typer.Context') -> 'ScanClient':
    client_id = ctx.obj.get('client_id')
    client_secret = ctx.obj.get('client_secret')
    hide_response_log = not ctx.obj.get('show_secret', False)
    return _get_cycode_client(create_scan_client, client_id, client_secret, hide_response_log)


def get_report_cycode_client(ctx: 'typer.Context', hide_response_log: bool = True) -> 'ReportClient':
    client_id = ctx.obj.get('client_id')
    client_secret = ctx.obj.get('client_secret')
    return _get_cycode_client(create_report_client, client_id, client_secret, hide_response_log)


def _get_configured_credentials() -> tuple[str, str]:
    credentials_manager = CredentialsManager()
    return credentials_manager.get_credentials()
