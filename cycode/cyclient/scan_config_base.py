from abc import ABC, abstractmethod

from cycode.cli import consts


class ScanConfigBase(ABC):
    @abstractmethod
    def get_service_name(self, scan_type: str, should_use_scan_service: bool = False) -> str:
        ...

    @staticmethod
    def get_async_scan_type(scan_type: str) -> str:
        if scan_type == 'secret':
            return 'Secrets'
        if scan_type == 'iac':
            return 'InfraConfiguration'

        return scan_type.upper()

    @staticmethod
    def get_async_entity_type(scan_type: str) -> str:
        if scan_type == consts.SECRET_SCAN_TYPE:
            return 'ZippedFile'
        # we are migrating to "zippedfile" entity type. will be used later
        return 'repository'

    @abstractmethod
    def get_detections_prefix(self) -> str:
        ...


class DevScanConfig(ScanConfigBase):
    def get_service_name(self, scan_type: str, should_use_scan_service: bool = False) -> str:
        if should_use_scan_service:
            return '5004'
        if scan_type == 'secret':
            return '5025'
        if scan_type == 'iac':
            return '5026'

        # sca and sast
        return '5004'

    def get_detections_prefix(self) -> str:
        return '5016'


class DefaultScanConfig(ScanConfigBase):
    def get_service_name(self, scan_type: str, should_use_scan_service: bool = False) -> str:
        if should_use_scan_service:
            return 'scans'
        if scan_type == 'secret':
            return 'secret'
        if scan_type == 'iac':
            return 'iac'

        # sca and sast
        return 'scans'

    def get_detections_prefix(self) -> str:
        return 'detections'
