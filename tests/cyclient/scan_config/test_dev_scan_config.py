from cyclient.scan_config.scan_config_creator import DevScanConfig


def test_get_service_name():
    dev_scan_config = DevScanConfig()

    assert dev_scan_config.get_service_name('secret') == '5025'
    assert dev_scan_config.get_service_name('iac') == '5026'
    assert dev_scan_config.get_service_name('sca') == '5004'
    assert dev_scan_config.get_service_name('sast') == '5004'


def test_get_scans_prefix():
    dev_scan_config = DevScanConfig()

    assert dev_scan_config.get_scans_prefix() == '5004'


def test_get_detections_prefix():
    dev_scan_config = DevScanConfig()

    assert dev_scan_config.get_detections_prefix() == '5016'
