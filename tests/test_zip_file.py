import os

from cycode.cli.utils.path_utils import concat_unique_id


def test_concat_unique_id_to_file_with_leading_slash() -> None:
    filename = os.path.join('path', 'to', 'file')  # we should care about slash characters in tests
    unique_id = 'unique_id'

    expected_path = os.path.join(unique_id, filename)

    filename = os.sep + filename
    assert concat_unique_id(filename, unique_id) == expected_path


def test_concat_unique_id_to_file_without_leading_slash() -> None:
    filename = os.path.join('path', 'to', 'file')  # we should care about slash characters in tests
    unique_id = 'unique_id'

    expected_path = os.path.join(unique_id, *filename.split('/'))

    assert concat_unique_id(filename, unique_id) == expected_path


def test_concat_unique_id_keeps_unique_id_for_windows_drive_path() -> None:
    # os.path.join drops the prefix when the file name is absolute; on Windows a drive letter makes it absolute,
    # which used to archive the file as 'C:/repo/file' and the server then reported 'C:' as the commit id
    unique_id = 'a' * 40

    # separators inside the file name are kept as-is; only the drive and the leading separator go away
    assert concat_unique_id('C:\\repo\\creds.txt', unique_id) == os.path.join(unique_id, 'repo\\creds.txt')
    assert concat_unique_id('C:/repo/creds.txt', unique_id) == os.path.join(unique_id, 'repo/creds.txt')


def test_concat_unique_id_keeps_unique_id_for_unc_path() -> None:
    unique_id = 'a' * 40

    assert concat_unique_id('\\\\server\\share\\creds.txt', unique_id) == os.path.join(unique_id, 'creds.txt')
