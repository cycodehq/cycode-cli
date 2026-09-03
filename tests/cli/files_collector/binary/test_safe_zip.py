import hashlib
import io
from pathlib import Path

import pytest

from cycode.cli import consts
from cycode.cli.exceptions.custom_exceptions import (
    ArchiveCompressionRatioLimitError,
    ArchiveEntryCountLimitError,
    ArchiveEntrySizeLimitError,
    ArchiveTotalSizeLimitError,
    BinaryExtractionError,
    MalformedArchiveError,
    UnsafeArchiveEntryError,
)
from cycode.cli.files_collector.binary.safe_zip import (
    ArchiveBudget,
    ArchiveLimits,
    SafeZip,
    validate_entry_name,
)
from tests.cli.files_collector.binary import fixtures


def _entry_names(archive: SafeZip) -> list[str]:
    return [entry.name for entry in archive.entries()]


class TestEntryNameValidation:
    @pytest.mark.parametrize(
        'name',
        [
            '../../evil.txt',
            'WEB-INF/lib/../../../evil.jar',
            '..',
            'a/../../b',
        ],
    )
    def test_path_escape_is_refused(self, name: str) -> None:
        with pytest.raises(UnsafeArchiveEntryError, match='escapes the archive root'):
            validate_entry_name(name)

    @pytest.mark.parametrize('name', ['/etc/passwd', '/', '/var/spool/cron/evil'])
    def test_absolute_path_is_refused(self, name: str) -> None:
        with pytest.raises(UnsafeArchiveEntryError, match='absolute path'):
            validate_entry_name(name)

    @pytest.mark.parametrize('name', ['C:\\Windows\\evil.dll', 'c:/windows/evil.dll', 'Z:relative'])
    def test_drive_letter_is_refused(self, name: str) -> None:
        with pytest.raises(UnsafeArchiveEntryError, match='drive letter'):
            validate_entry_name(name)

    @pytest.mark.parametrize('name', ['\\\\host\\share\\evil.txt', '//host/share/evil.txt'])
    def test_unc_path_is_refused(self, name: str) -> None:
        with pytest.raises(UnsafeArchiveEntryError, match='UNC path'):
            validate_entry_name(name)

    @pytest.mark.parametrize(
        'name',
        ['CON', 'nul', 'COM1', 'LPT9', 'CON.txt', 'aux.tar.gz', 'WEB-INF/lib/PRN.jar'],
    )
    def test_windows_reserved_name_is_refused(self, name: str) -> None:
        with pytest.raises(UnsafeArchiveEntryError, match='reserved device name'):
            validate_entry_name(name)

    def test_null_byte_is_refused(self) -> None:
        with pytest.raises(UnsafeArchiveEntryError, match='null byte'):
            validate_entry_name('evil\x00.txt')

    def test_empty_name_is_refused(self) -> None:
        with pytest.raises(UnsafeArchiveEntryError, match='empty name'):
            validate_entry_name('')

    @pytest.mark.parametrize(
        'name',
        [
            'WEB-INF/lib/guava-31.1-jre.jar',
            'META-INF/maven/com.google.guava/guava/pom.properties',
            'a/./b/c.txt',
            'CONTENTS.txt',
            'COMMON/thing.jar',
            'lpt.txt',
        ],
    )
    def test_ordinary_names_are_accepted(self, name: str) -> None:
        validate_entry_name(name)

    def test_every_refusal_is_a_binary_extraction_error(self) -> None:
        # phase 3 registers one error class in the scan error map; every refusal here must be caught by it
        with pytest.raises(BinaryExtractionError):
            validate_entry_name('../evil')


class TestUnsafeArchivesAreRefusedOnIteration:
    def test_zip_slip(self) -> None:
        with SafeZip.open(fixtures.zip_slip_bytes()) as archive, pytest.raises(UnsafeArchiveEntryError):
            _entry_names(archive)

    def test_absolute_path(self) -> None:
        with SafeZip.open(fixtures.absolute_path_bytes()) as archive, pytest.raises(UnsafeArchiveEntryError):
            _entry_names(archive)

    def test_drive_letter(self) -> None:
        with SafeZip.open(fixtures.drive_letter_bytes()) as archive, pytest.raises(UnsafeArchiveEntryError):
            _entry_names(archive)

    def test_unc_path(self) -> None:
        with SafeZip.open(fixtures.unc_path_bytes()) as archive, pytest.raises(UnsafeArchiveEntryError):
            _entry_names(archive)

    def test_reserved_device_name(self) -> None:
        with SafeZip.open(fixtures.reserved_name_bytes()) as archive, pytest.raises(UnsafeArchiveEntryError):
            _entry_names(archive)


class TestNonRegularEntries:
    def test_symlink_entry_is_skipped_not_followed(self) -> None:
        with SafeZip.open(fixtures.symlink_bytes()) as archive:
            names = _entry_names(archive)

        assert names == ['real.txt']

    def test_fifo_entry_is_skipped(self) -> None:
        with SafeZip.open(fixtures.non_regular_entry_bytes()) as archive:
            names = _entry_names(archive)

        assert names == ['real.txt']

    def test_msdos_created_entry_is_still_read(self) -> None:
        # windows tooling records no unix mode; treating "no opinion" as "not a regular file" would drop everything
        with SafeZip.open(fixtures.msdos_created_bytes()) as archive:
            names = _entry_names(archive)

        assert names == ['real.txt']

    def test_directory_entries_are_skipped(self) -> None:
        content = fixtures.archive_bytes(
            files={'WEB-INF/': '', 'WEB-INF/web.xml': '<web-app/>'},
            external_attrs={'WEB-INF/': fixtures.DIRECTORY_ATTR},
        )
        with SafeZip.open(content) as archive:
            names = _entry_names(archive)

        assert names == ['WEB-INF/web.xml']


class TestReading:
    def test_digests_match_the_content(self) -> None:
        payload = b'the quick brown fox' * 100
        with SafeZip.open(fixtures.archive_bytes(files={'a.bin': payload})) as archive:
            entry = next(iter(archive.entries()))
            content = archive.read(entry)

        assert content.data == payload
        assert content.size == len(payload)
        assert content.sha1 == hashlib.sha1(payload, usedforsecurity=False).hexdigest()
        assert content.sha256 == hashlib.sha256(payload).hexdigest()

    def test_digest_only_read_holds_no_bytes(self) -> None:
        payload = b'x' * 4096
        with SafeZip.open(fixtures.archive_bytes(files={'a.bin': payload})) as archive:
            entry = next(iter(archive.entries()))
            content = archive.read(entry, buffer=False)

        assert content.data is None
        assert content.size == len(payload)
        assert content.sha1 == hashlib.sha1(payload, usedforsecurity=False).hexdigest()

    def test_empty_archive_yields_nothing(self) -> None:
        with SafeZip.open(fixtures.empty_archive_bytes()) as archive:
            assert _entry_names(archive) == []

    def test_opens_from_a_path(self, tmp_path: Path) -> None:
        path = tmp_path / 'app.jar'
        path.write_bytes(fixtures.archive_bytes(files={'a.txt': 'a'}))

        with SafeZip.open(str(path)) as archive:
            assert _entry_names(archive) == ['a.txt']
            assert archive.source_name == 'app.jar'

    def test_opens_from_a_stream(self) -> None:
        stream = io.BytesIO(fixtures.archive_bytes(files={'a.txt': 'a'}))

        with SafeZip.open(stream, source_name='streamed.jar') as archive:
            assert _entry_names(archive) == ['a.txt']
            assert archive.source_name == 'streamed.jar'


class TestMalformedArchives:
    def test_bytes_that_are_not_a_zip(self) -> None:
        with pytest.raises(MalformedArchiveError, match='not a readable archive'):
            SafeZip.open(fixtures.not_a_zip_bytes(), source_name='app.jar')

    def test_truncated_central_directory(self) -> None:
        with pytest.raises(MalformedArchiveError):
            SafeZip.open(fixtures.truncated_central_directory_bytes(), source_name='app.jar')

    def test_malformed_local_header_fails_on_read_not_on_open(self) -> None:
        with SafeZip.open(fixtures.malformed_local_header_bytes(), source_name='app.jar') as archive:
            entry = next(iter(archive.entries()))
            with pytest.raises(MalformedArchiveError, match='could not be read'):
                archive.read(entry)

    def test_missing_file_is_a_clean_error_not_a_traceback(self, tmp_path: Path) -> None:
        with pytest.raises(MalformedArchiveError):
            SafeZip.open(str(tmp_path / 'absent.jar'))


class TestLimits:
    def test_shipped_limits_are_the_documented_ones(self) -> None:
        limits = ArchiveLimits()

        assert limits.max_entry_count == consts.BINARY_MAX_ENTRY_COUNT == 100_000
        assert limits.max_entry_size_in_bytes == consts.BINARY_MAX_ENTRY_SIZE_IN_BYTES == 512 * 1024 * 1024
        assert limits.max_total_size_in_bytes == consts.BINARY_MAX_TOTAL_SIZE_IN_BYTES == 2 * 1024 * 1024 * 1024
        assert limits.max_compression_ratio == consts.BINARY_MAX_COMPRESSION_RATIO == 200

    def test_entry_count_ceiling(self) -> None:
        budget = ArchiveBudget(ArchiveLimits(max_entry_count=5))

        with pytest.raises(ArchiveEntryCountLimitError, match='past the limit of 5'):
            SafeZip.open(fixtures.count_bomb_bytes(6), budget=budget)

    def test_entry_count_at_the_ceiling_is_allowed(self) -> None:
        budget = ArchiveBudget(ArchiveLimits(max_entry_count=5))

        with SafeZip.open(fixtures.count_bomb_bytes(5), budget=budget) as archive:
            assert len(_entry_names(archive)) == 5

    def test_declared_entry_size_is_refused_before_any_read(self) -> None:
        budget = ArchiveBudget(ArchiveLimits(max_entry_size_in_bytes=1024))

        with SafeZip.open(fixtures.size_bomb_bytes(), budget=budget) as archive:
            entry = next(iter(archive.entries()))
            with pytest.raises(ArchiveEntrySizeLimitError, match='declares'):
                archive.read(entry)

        assert budget.consumed_bytes == 0

    def test_entry_size_is_enforced_mid_stream_when_the_header_lies(self) -> None:
        budget = ArchiveBudget(ArchiveLimits(max_entry_size_in_bytes=1024))
        content = fixtures.size_bomb_bytes(uncompressed_size=64 * 1024)

        with SafeZip.open(content, budget=budget) as archive:
            entry = next(iter(archive.entries()))
            # forge a header that understates the payload, exactly as a hostile archive would
            liar = type(entry)(name=entry.name, size=16, compress_size=entry.compress_size)
            with pytest.raises(ArchiveEntrySizeLimitError, match='expands past'):
                archive.read(liar)

        # the abort happened while streaming rather than after the whole entry was in memory
        assert budget.consumed_bytes <= 1024 + 64 * 1024

    def test_total_size_ceiling_across_entries(self) -> None:
        budget = ArchiveBudget(ArchiveLimits(max_total_size_in_bytes=48 * 1024))
        content = fixtures.total_size_bomb_bytes(entry_count=8, entry_size=16 * 1024)

        with SafeZip.open(content, budget=budget) as archive, pytest.raises(ArchiveTotalSizeLimitError):
            for entry in archive.entries():
                archive.read(entry)

    def test_compression_ratio_ceiling_at_shipped_limits(self) -> None:
        with SafeZip.open(fixtures.ratio_bomb_bytes()) as archive:
            entry = next(iter(archive.entries()))
            with pytest.raises(ArchiveCompressionRatioLimitError, match='decompression bomb'):
                archive.read(entry)

    def test_ratio_ceiling_ignores_small_highly_compressible_files(self) -> None:
        # a few kilobytes of whitespace in a legitimate pom easily beats 200:1; only sustained expansion is a bomb
        payload = b' ' * 8192
        with SafeZip.open(fixtures.archive_bytes(files={'pom.xml': payload})) as archive:
            entry = next(iter(archive.entries()))
            assert archive.read(entry).size == len(payload)

    def test_ratio_abort_happens_before_full_expansion(self) -> None:
        uncompressed_size = 8 * 1024 * 1024
        budget = ArchiveBudget()

        with SafeZip.open(fixtures.ratio_bomb_bytes(uncompressed_size), budget=budget) as archive:
            entry = next(iter(archive.entries()))
            with pytest.raises(ArchiveCompressionRatioLimitError):
                archive.read(entry)

        assert budget.consumed_bytes < uncompressed_size


class TestBudgetSharing:
    def test_a_shared_budget_accumulates_across_archives(self) -> None:
        budget = ArchiveBudget(ArchiveLimits(max_total_size_in_bytes=48 * 1024))
        payload = b'C' * (16 * 1024)
        content = fixtures.archive_bytes(files={'a.bin': payload}, compress=False)

        for _ in range(3):
            with SafeZip.open(content, budget=budget) as archive:
                entry = next(iter(archive.entries()))
                archive.read(entry)

        assert budget.consumed_bytes == 48 * 1024

        with SafeZip.open(content, budget=budget) as archive:
            entry = next(iter(archive.entries()))
            with pytest.raises(ArchiveTotalSizeLimitError):
                archive.read(entry)
