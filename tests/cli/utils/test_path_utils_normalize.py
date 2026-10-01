import pytest

from cycode.cli.utils.path_utils import normalize_file_path


@pytest.mark.parametrize(
    ('path', 'expected'),
    [
        ('/repo/creds.txt', 'repo/creds.txt'),
        ('./repo/creds.txt', 'repo/creds.txt'),
        ('repo/creds.txt', 'repo/creds.txt'),
        ('C:\\repo\\creds.txt', 'repo\\creds.txt'),
        ('C:/repo/creds.txt', 'repo/creds.txt'),
        ('.\\repo\\creds.txt', 'repo\\creds.txt'),
        ('\\\\server\\share\\creds.txt', 'creds.txt'),
    ],
)
def test_normalize_file_path(path: str, expected: str) -> None:
    assert normalize_file_path(path) == expected
