from cycode.cyclient.config import dev_mode
from cycode.cyclient.config_dev import DEV_CYCODE_API_URL
from cycode.cyclient.cycode_dev_based_client import CycodeDevBasedClient
from cycode.cyclient.cycode_token_based_client import CycodeTokenBasedClient
from cycode.cyclient.report_client import ReportClient
from cycode.cyclient.scan_client import ScanClient
from cycode.cyclient.scan_config_base import DefaultScanConfig, DevScanConfig


def create_scan_client(client_id: str, client_secret: str, hide_response_log: bool) -> ScanClient:
    if dev_mode:
        client = CycodeDevBasedClient(DEV_CYCODE_API_URL)
        scan_config = DevScanConfig()
    else:
        client = CycodeTokenBasedClient(client_id, client_secret)
        scan_config = DefaultScanConfig()

    return ScanClient(client, scan_config, hide_response_log)


def create_report_client(client_id: str, client_secret: str, hide_response_log: bool) -> ReportClient:
    client = CycodeDevBasedClient(DEV_CYCODE_API_URL) if dev_mode else CycodeTokenBasedClient(client_id, client_secret)
    return ReportClient(client, hide_response_log)
