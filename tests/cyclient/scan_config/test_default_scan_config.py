from cyclient.scan_config.scan_config_creator import DefaultScanConfig


def test_get_service_name():
    default_scan_config = DefaultScanConfig()

    assert default_scan_config.get_service_name('secret') == 'secret'
    assert default_scan_config.get_service_name('iac') == 'iac'
    assert default_scan_config.get_service_name('sca') == 'scans'
    assert default_scan_config.get_service_name('sast') == 'scans'


def test_get_scans_prefix():
    default_scan_config = DefaultScanConfig()

    assert default_scan_config.get_scans_prefix() == 'scans'


def test_get_detections_prefix():
    default_scan_config = DefaultScanConfig()

    assert default_scan_config.get_detections_prefix() == 'detections'
