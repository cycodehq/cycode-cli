import os

from cycode.cli.apps.scan.scan_result import _get_file_name_from_detection
from cycode.cli.consts import IAC_SCAN_TYPE, SAST_SCAN_TYPE, SCA_SCAN_TYPE, SECRET_SCAN_TYPE


def test_get_file_name_from_detection_sca_uses_file_path() -> None:
    raw_detection = {
        'detection_details': {
            'file_name': 'package.json',
            'file_path': '/repo/path/package.json',
        },
    }
    result = _get_file_name_from_detection(SCA_SCAN_TYPE, raw_detection)
    assert result == '/repo/path/package.json'


def test_get_file_name_from_detection_iac_uses_file_path() -> None:
    raw_detection = {
        'detection_details': {
            'file_name': 'main.tf',
            'file_path': '/repo/infra/main.tf',
        },
    }
    result = _get_file_name_from_detection(IAC_SCAN_TYPE, raw_detection)
    assert result == '/repo/infra/main.tf'


def test_get_file_name_from_detection_sast_uses_file_path() -> None:
    raw_detection = {
        'detection_details': {
            'file_path': '/repo/src/app.py',
        },
    }
    result = _get_file_name_from_detection(SAST_SCAN_TYPE, raw_detection)
    assert result == '/repo/src/app.py'


def test_get_file_name_from_detection_secret_uses_file_path_and_file_name() -> None:
    raw_detection = {
        'detection_details': {
            'file_path': '/repo/src',
            'file_name': '.env',
        },
    }
    result = _get_file_name_from_detection(SECRET_SCAN_TYPE, raw_detection)
    assert result == os.path.join('/repo/src', '.env')
