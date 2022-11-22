from cli import zip_file


def test_concat_unique_id_to_file_starting_with_seperator():
    assert zip_file.concat_unique_id('/path/to/file', 'unique_id') == 'unique_id/path/to/file'


def test_concat_unique_id_to_file_starting_without_seperator():
    assert zip_file.concat_unique_id('path/to/file', 'unique_id') == 'unique_id/path/to/file'
