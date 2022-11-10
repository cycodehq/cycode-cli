import os
from pathlib import Path
from cli import code_scanner

test_files_path = os.path.join(Path(__file__).parent.absolute(), 'test_files')


def test_is_relevant_file_to_scan_sca():
    path = os.path.join(test_files_path, 'package.json')
    assert code_scanner._is_relevant_file_to_scan('sca', path) is True
