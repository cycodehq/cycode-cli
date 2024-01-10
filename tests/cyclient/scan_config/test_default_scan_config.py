from cycode.cyclient.scan_config_base import DefaultScanConfig


def test_get_service_name() -> None:
    default_scan_config = DefaultScanConfig()

    assert default_scan_config.get_service_name('secret') == 'secret'
    assert default_scan_config.get_service_name('iac') == 'iac'
    assert default_scan_config.get_service_name('sca') == 'scans'
    assert default_scan_config.get_service_name('sast') == 'scans'


def test_get_detections_prefix() -> None:
    default_scan_config = DefaultScanConfig()

    assert default_scan_config.get_detections_prefix() == 'detections'
