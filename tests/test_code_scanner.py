import os

from cycode.cli import code_scanner
from tests.conftest import TEST_FILES_PATH


def test_is_relevant_file_to_scan_sca() -> None:
    path = os.path.join(TEST_FILES_PATH, 'package.json')
    assert code_scanner._is_relevant_file_to_scan('sca', path) is True
