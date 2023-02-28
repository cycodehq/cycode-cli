from cyclient.config import dev_mode
from cyclient.config_dev import DEV_CYCODE_API_URL
from cyclient.cycode_dev_based_client import CycodeDevBasedClient
from cyclient.cycode_token_based_client import CycodeTokenBasedClient
from cyclient.scan_client import ScanClient
from cyclient.scan_config.scan_config_base import DefaultScanConfig, DevScanConfig


def create_scan_client(client_id, client_secret):
    if dev_mode:
        scan_cycode_client, scan_config = create_scan_for_dev_env()
    else:
        scan_cycode_client, scan_config = create_scan(client_id, client_secret)

    return ScanClient(scan_cycode_client=scan_cycode_client,
                      scan_config=scan_config)


def create_scan(client_id, client_secret):
    scan_cycode_client = CycodeTokenBasedClient(client_id, client_secret)
    scan_config = DefaultScanConfig()
    return scan_cycode_client, scan_config


def create_scan_for_dev_env():
    scan_cycode_client = CycodeDevBasedClient(DEV_CYCODE_API_URL)
    scan_config = DevScanConfig()
    return scan_cycode_client, scan_config
