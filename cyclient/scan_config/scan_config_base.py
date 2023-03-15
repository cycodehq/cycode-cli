from abc import ABC, abstractmethod


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
        elif scan_type == 'iac':
            return '5026'
        elif scan_type == 'sca' or scan_type == 'sast':
            return '5004'

    def get_scans_prefix(self):
        return '5004'

    def get_detections_prefix(self):
        return '5016'


class DefaultScanConfig(ScanConfigBase):

    def get_service_name(self, scan_type):
        if scan_type == 'secret':
            return 'secret'
        elif scan_type == 'iac':
            return 'iac'
        elif scan_type == 'sca' or scan_type == 'sast':
            return 'scans'

    def get_scans_prefix(self):
        return 'scans'

    def get_detections_prefix(self):
        return 'detections'
