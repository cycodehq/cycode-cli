from abc import ABC, abstractmethod


class ScanConfigBase(ABC):
    @abstractmethod
    def get_service_name(self, scan_type: str) -> str:
        ...

    @abstractmethod
    def get_scans_prefix(self) -> str:
        ...

    @abstractmethod
    def get_detections_prefix(self) -> str:
        ...


class DevScanConfig(ScanConfigBase):
    def get_service_name(self, scan_type: str) -> str:
        if scan_type == 'secret':
            return '5025'
        if scan_type == 'iac':
            return '5026'

        # sca and sast
        return '5004'

    def get_scans_prefix(self) -> str:
        return '5004'

    def get_detections_prefix(self) -> str:
        return '5016'


class DefaultScanConfig(ScanConfigBase):
    def get_service_name(self, scan_type: str) -> str:
        if scan_type == 'secret':
            return 'secret'
        if scan_type == 'iac':
            return 'iac'

        # sca and sast
        return 'scans'

    def get_scans_prefix(self) -> str:
        return 'scans'

    def get_detections_prefix(self) -> str:
        return 'detections'
