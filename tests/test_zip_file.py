from cli import zip_file


def test_concat_unique_id():
    assert zip_file.concat_unique_id('path/to/file', 'unique_id') == 'unique_id/path/to/file'
    assert zip_file.concat_unique_id('/path/to/file', 'unique_id') == 'unique_id/path/to/file'
