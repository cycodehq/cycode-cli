import multiprocessing
import os
from pathlib import Path

import pytest
import yaml
from pyfakefs.fake_filesystem import FakeFilesystem

from cycode.cli.utils.yaml_utils import read_yaml_file, update_yaml_file, write_yaml_file

# refresh_access_token() persists a ~900 char JWT, invalidate_access_token() persists nulls.
# That size gap is what let a short write leave a longer write's tail behind it.
_LONG_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.' + ('A' * 800) + '.signature'
_ITERATIONS = 200

_CLIENT_ID = 'b3a1f2c4-1111-2222-3333-444455556666'
_CORRUPT_CONTENT = 'cycode_client_id: valid\nycode_client_id\nleftover tail\n'

_DIRECTORY = '/home/user/.cycode'
_FILENAME = f'{_DIRECTORY}/credentials.yaml'


def _write_long_token(filename: str) -> None:
    for _ in range(_ITERATIONS):
        update_yaml_file(
            filename,
            {
                'cycode_access_token': _LONG_TOKEN,
                'cycode_access_token_creator': 'h' * 64,
                'cycode_access_token_expires_in': 1755000000.123456,
            },
        )


def _write_null_token(filename: str) -> None:
    for _ in range(_ITERATIONS):
        update_yaml_file(
            filename,
            {
                'cycode_access_token': None,
                'cycode_access_token_creator': None,
                'cycode_access_token_expires_in': None,
            },
        )


# Real processes cannot see a pyfakefs filesystem, so this one case has to touch the disk.
def test_concurrent_updates_never_corrupt_the_file(tmp_path: Path) -> None:
    filename = str(tmp_path / 'credentials.yaml')
    write_yaml_file(filename, {'cycode_client_id': _CLIENT_ID, 'cycode_client_secret': 's' * 40})

    context = multiprocessing.get_context('spawn')
    processes = [context.Process(target=target, args=(filename,)) for target in (_write_long_token, _write_null_token)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=120)
        assert process.exitcode == 0, f'writer process failed with exit code {process.exitcode}'

    with open(filename, encoding='UTF-8') as file:
        content = yaml.safe_load(file)

    assert isinstance(content, dict)
    assert content['cycode_client_id'] == _CLIENT_ID


def test_reading_a_corrupt_file_quarantines_it_and_returns_empty(fs: FakeFilesystem) -> None:
    fs.create_file(_FILENAME, contents=_CORRUPT_CONTENT)

    assert read_yaml_file(_FILENAME) == {}
    assert not os.path.exists(_FILENAME)

    quarantined = list(Path(_DIRECTORY).glob('credentials.yaml.corrupt-*'))
    assert len(quarantined) == 1
    assert quarantined[0].read_text(encoding='UTF-8') == _CORRUPT_CONTENT


def test_updating_a_corrupt_file_recovers_instead_of_raising(fs: FakeFilesystem) -> None:
    fs.create_file(_FILENAME, contents=_CORRUPT_CONTENT)

    update_yaml_file(_FILENAME, {'cycode_client_id': 'recovered'})

    assert read_yaml_file(_FILENAME) == {'cycode_client_id': 'recovered'}


def test_quarantine_does_not_overwrite_an_earlier_quarantined_file(fs: FakeFilesystem) -> None:
    fs.create_dir(_DIRECTORY)
    for marker in ('first', 'second'):
        with open(_FILENAME, 'w', encoding='UTF-8') as file:
            file.write(f'{marker}\nnot: [valid\n')
        read_yaml_file(_FILENAME)

    quarantined = [path.read_text(encoding='UTF-8') for path in Path(_DIRECTORY).glob('credentials.yaml.corrupt-*')]

    assert len(quarantined) == 2
    assert any('first' in content for content in quarantined)
    assert any('second' in content for content in quarantined)


@pytest.mark.parametrize('read_only_path', [_DIRECTORY, _FILENAME])
def test_write_is_skipped_on_a_read_only_filesystem(fs: FakeFilesystem, read_only_path: str) -> None:
    fs.create_dir(_DIRECTORY)
    write_yaml_file(_FILENAME, {'cycode_client_id': 'original'})
    fs.chmod(read_only_path, 0o500)

    write_yaml_file(_FILENAME, {'cycode_client_id': 'updated'})

    fs.chmod(read_only_path, 0o700)
    assert read_yaml_file(_FILENAME) == {'cycode_client_id': 'original'}


def test_write_leaves_no_temporary_files_behind(fs: FakeFilesystem) -> None:
    fs.create_dir(_DIRECTORY)
    write_yaml_file(_FILENAME, {'cycode_client_id': _CLIENT_ID})

    assert [path.name for path in Path(_DIRECTORY).iterdir()] == ['credentials.yaml']
