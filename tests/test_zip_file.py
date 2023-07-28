import os

from cycode.cli import zip_file


def test_concat_unique_id_to_file_with_leading_slash() -> None:
    filename = os.path.join('path', 'to', 'file')  # we should care about slash characters in tests
    unique_id = 'unique_id'

    expected_path = os.path.join(unique_id, filename)

    filename = os.sep + filename
    assert zip_file.concat_unique_id(filename, unique_id) == expected_path


def test_concat_unique_id_to_file_without_leading_slash() -> None:
    filename = os.path.join('path', 'to', 'file')  # we should care about slash characters in tests
    unique_id = 'unique_id'

    expected_path = os.path.join(unique_id, *filename.split('/'))

    assert zip_file.concat_unique_id(filename, unique_id) == expected_path
