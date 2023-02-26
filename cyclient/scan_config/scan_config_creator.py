from cyclient.config import dev_mode
from cyclient.config_dev import DEV_SCAN_CYCODE_APP_URL, DEV_DETECTION_CYCODE_APP_URL
from cyclient.cycode_dev_based_client import CycodeDevBasedClient
from cyclient.cycode_token_based_client import CycodeTokenBasedClient
from cyclient.scan_client import ScanClient
from cyclient.scan_config.default_scan_config import DefaultScanConfig
from cyclient.scan_config.dev_scan_config import DevScanConfig


def create_scan_for_env(client_id, client_secret):
    if dev_mode:
        detection_cycode_client, scan_config, scan_cycode_client = create_scan_for_dev_env()
    else:
        detection_cycode_client, scan_config, scan_cycode_client = create_scan(client_id, client_secret)

    return ScanClient(scan_cycode_client=scan_cycode_client, detection_cycode_client=detection_cycode_client,
                      scan_config=scan_config)

def create_scan(client_id, client_secret):
    cycode_client = CycodeTokenBasedClient(client_id, client_secret)
    scan_config = DefaultScanConfig()
    return cycode_client, scan_config, cycode_client


def create_scan_for_dev_env():
    scan_cycode_client = CycodeDevBasedClient(DEV_SCAN_CYCODE_APP_URL)
    detection_cycode_client = CycodeDevBasedClient(DEV_DETECTION_CYCODE_APP_URL)
    scan_config = DevScanConfig()
    return detection_cycode_client, scan_config, scan_cycode_client