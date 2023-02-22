from cyclient.scan_config.ScanConfigBase import ScanConfigBase


class DevScanConfig(ScanConfigBase):
    def __init__(self):
        self.SCAN_SERVICE_CONTROLLER_PATH = 'api/v1/scan'
        self.DETECTIONS_SERVICE_CONTROLLER_PATH = 'api/v1/detections'
