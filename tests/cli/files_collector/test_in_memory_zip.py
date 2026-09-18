"""Tests for InMemoryZip class, specifically for handling surrogate characters and encoding issues."""

import zipfile
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock
from uuid import uuid4

import pytest

from cycode.cli import consts
from cycode.cli.files_collector.models.in_memory_zip import InMemoryZip

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


def test_append_with_surrogate_characters() -> None:
    """Test that surrogate characters are handled gracefully without raising encoding errors."""
    # Surrogate characters (U+D800 to U+DFFF) cannot be encoded to UTF-8 directly
    zip_file = InMemoryZip()
    content = 'Normal text \udc96 more text'

    # Should not raise UnicodeEncodeError
    zip_file.append('test.txt', None, content)
    zip_file.close()

    # Verify the ZIP was created successfully
    zip_data = zip_file.read()
    assert len(zip_data) > 0

    # Verify we can read it back and the surrogate was replaced
    with zipfile.ZipFile(BytesIO(zip_data), 'r') as zf:
        extracted = zf.read('test.txt').decode('utf-8')
        assert 'Normal text' in extracted
        assert 'more text' in extracted
        # The surrogate should have been replaced with the replacement character
        assert '\udc96' not in extracted


@pytest.mark.parametrize(('is_64bit', 'expected_allow_zip64'), [(True, True), (False, False)])
def test_allow_zip64_follows_interpreter_bitness(
    monkeypatch: 'MonkeyPatch', is_64bit: bool, expected_allow_zip64: bool
) -> None:
    """ZIP64 requires 64-bit offsets, so it's enabled only on a 64-bit interpreter."""
    monkeypatch.setattr('cycode.cli.files_collector.models.in_memory_zip.is_64bit', lambda: is_64bit)

    zip_file = InMemoryZip()

    assert zip_file.allow_zip64 is expected_allow_zip64
    assert zip_file.zip._allowZip64 is expected_allow_zip64


def test_append_more_files_than_non_zip64_limit_on_64bit(monkeypatch: 'MonkeyPatch') -> None:
    """With ZIP64 enabled, the archive holds more than 65,535 entries."""
    monkeypatch.setattr('cycode.cli.files_collector.models.in_memory_zip.is_64bit', lambda: True)

    files_count = consts.ZIP_MAX_FILES_COUNT + 1
    zip_file = InMemoryZip()
    for index in range(files_count):
        zip_file.append(f'file_{index}.txt', None, 'content')
    zip_file.close()

    with zipfile.ZipFile(BytesIO(zip_file.read()), 'r') as zf:
        assert len(zf.namelist()) == files_count

    assert zip_file.files_count == files_count


def test_append_more_files_than_non_zip64_limit_on_32bit(monkeypatch: 'MonkeyPatch') -> None:
    """Without ZIP64, appending past 65,535 entries raises instead of silently truncating."""
    monkeypatch.setattr('cycode.cli.files_collector.models.in_memory_zip.is_64bit', lambda: False)

    zip_file = InMemoryZip()
    with pytest.raises(zipfile.LargeZipFile):
        for index in range(consts.ZIP_MAX_FILES_COUNT + 1):
            zip_file.append(f'file_{index}.txt', None, 'content')


def test_size_is_the_real_archive_length() -> None:
    """The size guard and the reported zip_size must reflect the actual bytes, not an approximation."""
    zip_file = InMemoryZip()
    zip_file.append('test.txt', None, 'content' * 1000)
    zip_file.close()

    assert zip_file.size == len(zip_file.read())


def test_stays_in_memory_below_the_spool_threshold(monkeypatch: 'MonkeyPatch') -> None:
    """Ordinary scans never touch the disk."""
    monkeypatch.setattr(consts, 'ZIP_SPOOL_MAX_SIZE_IN_BYTES', 1024 * 1024)

    zip_file = InMemoryZip()
    zip_file.append('test.txt', None, 'content')
    zip_file.close()

    assert zip_file.is_rolled_over is False


def test_rolls_over_to_disk_above_the_spool_threshold(monkeypatch: 'MonkeyPatch') -> None:
    """A big archive spills into a temp file instead of growing the heap, and still reads back intact."""
    monkeypatch.setattr(consts, 'ZIP_SPOOL_MAX_SIZE_IN_BYTES', 1024)

    zip_file = InMemoryZip()
    for index in range(100):
        # random-ish content so deflate can't compress it away below the threshold
        zip_file.append(f'file_{index}.txt', None, str(uuid4()) * 100)
    zip_file.close()

    assert zip_file.is_rolled_over is True
    with zipfile.ZipFile(BytesIO(zip_file.read()), 'r') as zf:
        assert len(zf.namelist()) == 100

    zip_file.cleanup()


def test_spills_into_the_cycode_configuration_directory(monkeypatch: 'MonkeyPatch', tmp_path: Path) -> None:
    """The temp file lands under the Cycode configuration directory, not in an arbitrary location."""
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    monkeypatch.setattr(consts, 'ZIP_SPOOL_MAX_SIZE_IN_BYTES', 1)

    zip_file = InMemoryZip()
    zip_file.append('test.txt', None, 'content')
    zip_file.close()

    assert zip_file.is_rolled_over is True
    assert (tmp_path / consts.CYCODE_CONFIGURATION_DIRECTORY / 'tmp').is_dir()

    zip_file.cleanup()


def test_falls_back_to_the_system_temp_directory(monkeypatch: 'MonkeyPatch') -> None:
    """An unwritable configuration directory (read-only CI runner) must not fail the scan."""
    monkeypatch.setattr(consts, 'ZIP_SPOOL_MAX_SIZE_IN_BYTES', 1)
    monkeypatch.setattr(
        'cycode.cli.files_collector.models.in_memory_zip.Path.mkdir',
        Mock(side_effect=PermissionError('read-only file system')),
    )

    zip_file = InMemoryZip()
    zip_file.append('test.txt', None, 'content')
    zip_file.close()

    with zipfile.ZipFile(BytesIO(zip_file.read()), 'r') as zf:
        assert zf.read('test.txt') == b'content'

    zip_file.cleanup()


def test_cleanup_is_idempotent() -> None:
    """Callers release the buffer in a finally block; a double release must not raise."""
    zip_file = InMemoryZip()
    zip_file.append('test.txt', None, 'content')
    zip_file.close()

    zip_file.cleanup()
    zip_file.cleanup()


def test_used_as_a_context_manager() -> None:
    zip_file = InMemoryZip()
    with zip_file as managed:
        managed.append('test.txt', None, 'content')
        managed.close()
        content = managed.read()

    assert len(content) > 0


def test_write_on_disk_matches_the_archive(tmp_path: Path) -> None:
    """The --debug dump streams the archive out instead of copying it through memory."""
    zip_file = InMemoryZip()
    zip_file.append('test.txt', None, 'content')
    zip_file.close()

    zip_file_path = tmp_path / 'dump.zip'
    zip_file.write_on_disk(zip_file_path)

    assert zip_file_path.read_bytes() == zip_file.read()


@pytest.mark.parametrize('spool_max_size', [1, 512, 1024 * 1024])
def test_is_rolled_over_matches_the_interpreter(monkeypatch: 'MonkeyPatch', spool_max_size: int) -> None:
    """Our size-based check must agree with CPython's own (private) rollover flag on every version."""
    monkeypatch.setattr(consts, 'ZIP_SPOOL_MAX_SIZE_IN_BYTES', spool_max_size)

    zip_file = InMemoryZip()
    for index in range(20):
        zip_file.append(f'file_{index}.txt', None, str(uuid4()) * 10)
    zip_file.close()

    rolled_by_interpreter = getattr(zip_file._buffer, '_rolled', None)
    if rolled_by_interpreter is not None:
        assert zip_file.is_rolled_over is rolled_by_interpreter

    zip_file.cleanup()
