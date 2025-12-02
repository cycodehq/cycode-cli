from typing import Optional

from cycode.cyclient.config import dev_mode
from cycode.cyclient.config_dev import DEV_CYCODE_API_URL
from cycode.cyclient.cycode_dev_based_client import CycodeDevBasedClient
from cycode.cyclient.cycode_oidc_based_client import CycodeOidcBasedClient
from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient
from cycode.cyclient.import_sbom_client import ImportSbomClient
from cycode.cyclient.report_client import ReportClient
from cycode.cyclient.scan_client import ScanClient
from cycode.cyclient.scan_config_base import DefaultScanConfig, DevScanConfig


def create_scan_client(
    client_id: str, client_secret: Optional[str] = None, hide_response_log: bool = False, id_token: Optional[str] = None
) -> ScanClient:
    if dev_mode:
        client = CycodeDevBasedClient(DEV_CYCODE_API_URL)
        scan_config = DevScanConfig()
    else:
        if id_token:
            client = CycodeOidcBasedClient(client_id, id_token)
        else:
            client = CycodeTokenBasedClient(client_id, client_secret)
        scan_config = DefaultScanConfig()

    return ScanClient(client, scan_config, hide_response_log)


def create_report_client(
    client_id: str, client_secret: Optional[str] = None, _: bool = False, id_token: Optional[str] = None
) -> ReportClient:
    if dev_mode:
        client = CycodeDevBasedClient(DEV_CYCODE_API_URL)
    elif id_token:
        client = CycodeOidcBasedClient(client_id, id_token)
    else:
        client = CycodeTokenBasedClient(client_id, client_secret)
    return ReportClient(client)


def create_import_sbom_client(
    client_id: str, client_secret: Optional[str] = None, _: bool = False, id_token: Optional[str] = None
) -> ImportSbomClient:
    if dev_mode:
        client = CycodeDevBasedClient(DEV_CYCODE_API_URL)
    elif id_token:
        client = CycodeOidcBasedClient(client_id, id_token)
    else:
        client = CycodeTokenBasedClient(client_id, client_secret)
    return ImportSbomClient(client)
