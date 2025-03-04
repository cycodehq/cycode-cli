from cycode.cli import consts
from cycode.cyclient.scan_config_base import DevScanConfig


def test_get_service_name() -> None:
    dev_scan_config = DevScanConfig()

    assert dev_scan_config.get_service_name(consts.SECRET_SCAN_TYPE) == '5025'
    assert dev_scan_config.get_service_name(consts.IAC_SCAN_TYPE) == '5026'
    assert dev_scan_config.get_service_name(consts.SCA_SCAN_TYPE) == '5004'
    assert dev_scan_config.get_service_name(consts.SAST_SCAN_TYPE) == '5004'
    assert dev_scan_config.get_service_name(consts.SECRET_SCAN_TYPE, should_use_scan_service=True) == '5004'


def test_get_detections_prefix() -> None:
    dev_scan_config = DevScanConfig()

    assert dev_scan_config.get_detections_prefix() == '5016'
