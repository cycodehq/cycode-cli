from cyclient import scan_client


def test_get_service_name():
    assert scan_client.ScanClient.get_service_name('secret') == 'secret'
    assert scan_client.ScanClient.get_service_name('iac') == 'iac'
    assert scan_client.ScanClient.get_service_name('sca') == 'scans'
    assert scan_client.ScanClient.get_service_name('sast') == 'scans'