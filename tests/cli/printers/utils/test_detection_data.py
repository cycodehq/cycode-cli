from pathlib import Path
from unittest.mock import MagicMock

from cycode.cli.consts import IAC_SCAN_TYPE, SAST_SCAN_TYPE, SCA_SCAN_TYPE, SECRET_SCAN_TYPE
from cycode.cli.printers.utils.detection_data import get_detection_file_path


def _make_detection(**details: str) -> MagicMock:
    detection = MagicMock()
    detection.detection_details = dict(details)
    return detection


def test_get_detection_file_path_sca_uses_file_path() -> None:
    detection = _make_detection(file_name='package.json', file_path='/repo/path/package.json')
    result = get_detection_file_path(SCA_SCAN_TYPE, detection)
    assert result == Path('/repo/path/package.json')


def test_get_detection_file_path_iac_uses_file_path() -> None:
    detection = _make_detection(file_name='main.tf', file_path='/repo/infra/main.tf')
    result = get_detection_file_path(IAC_SCAN_TYPE, detection)
    assert result == Path('/repo/infra/main.tf')


def test_get_detection_file_path_sca_fallback_empty() -> None:
    detection = _make_detection()
    result = get_detection_file_path(SCA_SCAN_TYPE, detection)
    assert result == Path('')


def test_get_detection_file_path_secret() -> None:
    detection = _make_detection(file_path='/repo/src', file_name='.env')
    result = get_detection_file_path(SECRET_SCAN_TYPE, detection)
    assert result == Path('/repo/src/.env')


def test_get_detection_file_path_sast() -> None:
    detection = _make_detection(file_path='repo/src/app.py')
    result = get_detection_file_path(SAST_SCAN_TYPE, detection)
    assert result == Path('/repo/src/app.py')
