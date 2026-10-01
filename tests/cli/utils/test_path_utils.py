from pathlib import PurePosixPath

import pytest

from cycode.cli.consts import OperatingSystem
from cycode.cli.utils.path_utils import _to_relative_posix_parts, concat_unique_id, normalize_file_path


def test_concat_unique_id_to_file_with_leading_slash() -> None:
    assert concat_unique_id('/path/to/file', 'unique_id') == 'unique_id/path/to/file'


def test_concat_unique_id_to_file_without_leading_slash() -> None:
    assert concat_unique_id('path/to/file', 'unique_id') == 'unique_id/path/to/file'


def test_concat_unique_id_keeps_unique_id_for_windows_drive_path() -> None:
    unique_id = 'a' * 40

    # the entry name is always posix: the drive and the root go away, backslashes become forward slashes
    for path in ('C:\\repo\\creds.txt', 'C:/repo/creds.txt'):
        parts = _to_relative_posix_parts(path, OperatingSystem.WINDOWS)
        assert str(PurePosixPath(unique_id, *parts)) == f'{unique_id}/repo/creds.txt'


def test_concat_unique_id_keeps_server_and_share_for_unc_path() -> None:
    unique_id = 'a' * 40

    # the server and the share are part of the path: two shares must not collapse onto the same entry
    parts = _to_relative_posix_parts('\\\\server\\share\\creds.txt', OperatingSystem.WINDOWS)
    assert str(PurePosixPath(unique_id, *parts)) == f'{unique_id}/server/share/creds.txt'


@pytest.mark.parametrize(
    ('path', 'expected'),
    [
        ('/repo/creds.txt', 'repo/creds.txt'),
        ('./repo/creds.txt', 'repo/creds.txt'),
        ('repo/creds.txt', 'repo/creds.txt'),
        ('', ''),
        # a colon is a legal character in a posix file name and must not be read as a drive
        ('x:y/creds.txt', 'x:y/creds.txt'),
    ],
)
def test_normalize_file_path_on_posix(path: str, expected: str) -> None:
    assert normalize_file_path(path) == expected


@pytest.mark.parametrize(
    ('path', 'expected'),
    [
        ('C:\\repo\\creds.txt', 'repo/creds.txt'),
        ('C:/repo/creds.txt', 'repo/creds.txt'),
        ('.\\repo\\creds.txt', 'repo/creds.txt'),
        ('/repo/creds.txt', 'repo/creds.txt'),
        # the server and the share are kept, so two shares do not normalize onto the same path
        ('\\\\server\\share\\creds.txt', 'server/share/creds.txt'),
        ('\\\\server\\other\\creds.txt', 'server/other/creds.txt'),
    ],
)
def test_normalize_file_path_on_windows(path: str, expected: str) -> None:
    assert str(PurePosixPath(*_to_relative_posix_parts(path, OperatingSystem.WINDOWS))) == expected
