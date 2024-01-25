from cycode.cyclient.scan_config_base import DevScanConfig


def test_get_service_name() -> None:
    dev_scan_config = DevScanConfig()

    assert dev_scan_config.get_service_name('secret') == '5025'
    assert dev_scan_config.get_service_name('iac') == '5026'
    assert dev_scan_config.get_service_name('sca') == '5004'
    assert dev_scan_config.get_service_name('sast') == '5004'
    assert dev_scan_config.get_service_name('secret', should_use_scan_service=True) == '5004'


def test_get_detections_prefix() -> None:
    dev_scan_config = DevScanConfig()

    assert dev_scan_config.get_detections_prefix() == '5016'
