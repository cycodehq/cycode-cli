import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.utils.yaml_utils import read_yaml_file, update_yaml_file, write_yaml_file

if TYPE_CHECKING:
    from pytest_mock import MockerFixture

_CLIENT_ID = 'b3a1f2c4-1111-2222-3333-444455556666'
_CORRUPT_CONTENT = 'cycode_client_id: valid\nycode_client_id\nleftover tail\n'

_DIRECTORY = '/home/user/.cycode'
_FILENAME = f'{_DIRECTORY}/credentials.yaml'


def test_reading_a_corrupt_file_quarantines_it_and_returns_empty(fs: FakeFilesystem) -> None:
    fs.create_dir(_DIRECTORY)

    for marker in ('first', 'second'):
        contents = f'{marker}\n{_CORRUPT_CONTENT}'
        with open(_FILENAME, 'w', encoding='UTF-8') as file:
            file.write(contents)

        assert read_yaml_file(_FILENAME) == {}
        assert not os.path.exists(_FILENAME)
        # only the most recent corrupt file is kept, so repeated failures cannot pile up
        assert [path.name for path in Path(_DIRECTORY).iterdir()] == ['credentials.yaml.corrupt']
        assert Path(f'{_FILENAME}.corrupt').read_text(encoding='UTF-8') == contents


def test_updating_a_corrupt_file_recovers_instead_of_raising(fs: FakeFilesystem) -> None:
    fs.create_file(_FILENAME, contents=_CORRUPT_CONTENT)

    update_yaml_file(_FILENAME, {'cycode_client_id': 'recovered'})

    assert read_yaml_file(_FILENAME) == {'cycode_client_id': 'recovered'}


@pytest.mark.parametrize('read_only_path', [_DIRECTORY, _FILENAME])
def test_write_is_skipped_on_a_read_only_filesystem(
    fs: FakeFilesystem, mocker: 'MockerFixture', read_only_path: str
) -> None:
    fs.create_dir(_DIRECTORY)
    write_yaml_file(_FILENAME, {'cycode_client_id': 'original'})

    real_access = os.access
    mocker.patch(
        'os.access',
        side_effect=lambda path, mode: (
            False if mode == os.W_OK and str(path) == read_only_path else real_access(path, mode)
        ),
    )

    write_yaml_file(_FILENAME, {'cycode_client_id': 'updated'})

    assert read_yaml_file(_FILENAME) == {'cycode_client_id': 'original'}


def test_write_leaves_no_temporary_files_behind(fs: FakeFilesystem) -> None:
    fs.create_dir(_DIRECTORY)
    write_yaml_file(_FILENAME, {'cycode_client_id': _CLIENT_ID})

    assert [path.name for path in Path(_DIRECTORY).iterdir()] == ['credentials.yaml']


# Stands in for a concurrent writer stopping partway through: the existing file must survive untouched,
# which is what truncating it up front could never guarantee.
def test_a_failed_write_leaves_the_existing_file_untouched(fs: FakeFilesystem, mocker: 'MockerFixture') -> None:
    fs.create_dir(_DIRECTORY)
    write_yaml_file(_FILENAME, {'cycode_client_id': 'original'})
    mocker.patch('yaml.safe_dump', side_effect=OSError('no space left on device'))

    with pytest.raises(OSError, match='no space left on device'):
        write_yaml_file(_FILENAME, {'cycode_client_id': 'updated'})

    mocker.stopall()
    assert read_yaml_file(_FILENAME) == {'cycode_client_id': 'original'}
    assert [path.name for path in Path(_DIRECTORY).iterdir()] == ['credentials.yaml']
