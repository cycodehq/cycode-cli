from cycode.cli import consts
from cycode.cyclient.scan_config_base import DefaultScanConfig


def test_get_service_name() -> None:
    default_scan_config = DefaultScanConfig()

    assert default_scan_config.get_service_name(consts.SECRET_SCAN_TYPE) == 'scans'
    assert default_scan_config.get_service_name(consts.IAC_SCAN_TYPE) == 'scans'
    assert default_scan_config.get_service_name(consts.SCA_SCAN_TYPE) == 'scans'
    assert default_scan_config.get_service_name(consts.SAST_SCAN_TYPE) == 'scans'


def test_get_detections_prefix() -> None:
    default_scan_config = DefaultScanConfig()

    assert default_scan_config.get_detections_prefix() == 'detections'
