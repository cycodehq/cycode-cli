from abc import ABC, abstractmethod

from cycode.cli import consts


class ScanConfigBase(ABC):
    @abstractmethod
    def get_service_name(self, scan_type: str) -> str: ...

    @staticmethod
    def get_async_scan_type(scan_type: str) -> str:
        if scan_type == consts.SECRET_SCAN_TYPE:
            return 'Secrets'
        if scan_type == consts.IAC_SCAN_TYPE:
            return 'InfraConfiguration'

        return scan_type.upper()

    @staticmethod
    def get_async_entity_type(scan_type: str) -> str:
        if scan_type == consts.SECRET_SCAN_TYPE:
            return 'ZippedFile'
        # we are migrating to "zippedfile" entity type. will be used later
        return 'repository'

    @abstractmethod
    def get_detections_prefix(self) -> str: ...


class DevScanConfig(ScanConfigBase):
    def get_service_name(self, scan_type: str) -> str:
        return '5004'  # scan service

    def get_detections_prefix(self) -> str:
        return '5016'  # detections service


class DefaultScanConfig(ScanConfigBase):
    def get_service_name(self, scan_type: str) -> str:
        return 'scans'  # scan service

    def get_detections_prefix(self) -> str:
        return 'detections'
