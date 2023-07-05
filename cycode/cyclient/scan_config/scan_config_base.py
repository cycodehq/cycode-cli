from abc import ABC, abstractmethod
from typing import Optional


class ScanConfigBase(ABC):
    @abstractmethod
    def get_service_name(self, scan_type):
        pass

    @abstractmethod
    def get_scans_prefix(self):
        pass

    @abstractmethod
    def get_detections_prefix(self):
        pass


class DevScanConfig(ScanConfigBase):
    def get_service_name(self, scan_type):
        if scan_type == 'secret':
            return '5025'
        if scan_type == 'iac':
            return '5026'
        if scan_type == 'sca' or scan_type == 'sast':
            return '5004'
        return None

    def get_scans_prefix(self):
        return '5004'

    def get_detections_prefix(self):
        return '5016'


class DefaultScanConfig(ScanConfigBase):
    def get_service_name(self, scan_type) -> Optional[str]:
        if scan_type == 'secret':
            return 'secret'
        if scan_type == 'iac':
            return 'iac'
        if scan_type == 'sca' or scan_type == 'sast':
            return 'scans'

        return None

    def get_scans_prefix(self):
        return 'scans'

    def get_detections_prefix(self):
        return 'detections'
