"""Hardened reader for untrusted zip-based archives.

Nothing here ever writes to disk. Entries are streamed into memory, capped as they are read, and nested archives
are reopened from the bytes already in hand. ``ZipFile.extract`` and ``ZipFile.extractall`` are never called: their
path handling is not ours to trust, and by never materialising a path we make zip slip unreachable rather than
merely defended against.
"""

import hashlib
import io
import os
import re
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from types import TracebackType
from typing import IO, Optional, Union

from cycode.cli import consts
from cycode.cli.exceptions.custom_exceptions import (
    ArchiveCompressionRatioLimitError,
    ArchiveEntryCountLimitError,
    ArchiveEntrySizeLimitError,
    ArchiveTotalSizeLimitError,
    MalformedArchiveError,
    UnsafeArchiveEntryError,
)

_READ_CHUNK_SIZE_IN_BYTES = 64 * 1024

_DRIVE_LETTER_PATTERN = re.compile(r'^[A-Za-z]:')

_WINDOWS_RESERVED_NAMES = frozenset(
    {'CON', 'PRN', 'AUX', 'NUL'}
    | {f'COM{ordinal}' for ordinal in range(1, 10)}
    | {f'LPT{ordinal}' for ordinal in range(1, 10)}
)

# unix file-type bits, carried in the high 16 bits of ZipInfo.external_attr
_UNIX_FILE_TYPE_MASK = 0o170000
_UNIX_REGULAR_FILE = 0o100000

# archives written by MS-DOS tooling record no unix mode at all, so a zero file type means "no opinion"
_UNIX_FILE_TYPE_UNSET = 0

# raised from inside zipfile when the bytes it was handed are not the archive they claim to be
_CORRUPT_ARCHIVE_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, OSError, ValueError)


@dataclass(frozen=True)
class ArchiveLimits:
    """Resource ceilings applied while reading an archive. Injectable so tests can prove a control cheaply."""

    max_entry_count: int = consts.BINARY_MAX_ENTRY_COUNT
    max_entry_size_in_bytes: int = consts.BINARY_MAX_ENTRY_SIZE_IN_BYTES
    max_total_size_in_bytes: int = consts.BINARY_MAX_TOTAL_SIZE_IN_BYTES
    max_compression_ratio: int = consts.BINARY_MAX_COMPRESSION_RATIO
    compression_ratio_floor_in_bytes: int = consts.BINARY_COMPRESSION_RATIO_FLOOR_IN_BYTES


DEFAULT_ARCHIVE_LIMITS = ArchiveLimits()


class ArchiveBudget:
    """Uncompressed-byte budget shared by an archive and every archive nested inside it.

    Sharing matters: a nest of archives that are each individually modest can still sum past the total cap, and a
    per-archive counter would never notice.
    """

    def __init__(self, limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS) -> None:
        self.limits = limits
        self.consumed_bytes = 0

    def consume(self, count: int) -> None:
        self.consumed_bytes += count
        if self.consumed_bytes > self.limits.max_total_size_in_bytes:
            raise ArchiveTotalSizeLimitError(
                f'Archive expands past the total uncompressed limit of {self.limits.max_total_size_in_bytes} bytes.'
            )


@dataclass(frozen=True)
class SafeZipEntry:
    """A regular-file entry that has already passed name validation."""

    name: str
    size: int  # uncompressed size as declared by the archive, which may be a lie
    compress_size: int
    # the central-directory record this entry came from. Reads go through it rather than through the name,
    # because ZipFile resolves a name to whichever duplicate happens to be last, which lets a crafted archive
    # hide a vulnerable jar behind a patched one carrying the same name.
    info: Optional[zipfile.ZipInfo] = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class EntryContent:
    """The result of reading one entry. ``data`` is None when the caller asked for digests only."""

    data: Optional[bytes]
    sha1: str
    sha256: str
    size: int  # bytes actually read, which is the number to trust


def validate_entry_name(name: str) -> None:
    """Refuse any entry name we would not be willing to reproduce on disk, on any operating system.

    We never write these paths out, but they are surfaced to users and may be joined by callers later, so they are
    validated at the point of entry rather than at the point of use.
    """
    if not name:
        raise UnsafeArchiveEntryError('Archive contains an entry with an empty name.')

    if '\x00' in name:
        raise UnsafeArchiveEntryError('Archive contains an entry whose name embeds a null byte.')

    # zip names are meant to use forward slashes; treat a backslash as a separator rather than a literal character,
    # because that is how Windows will read it
    normalized = name.replace('\\', '/')

    if normalized.startswith('//'):
        raise UnsafeArchiveEntryError(f'Archive entry uses a UNC path: {name!r}.')

    if normalized.startswith('/'):
        raise UnsafeArchiveEntryError(f'Archive entry uses an absolute path: {name!r}.')

    if _DRIVE_LETTER_PATTERN.match(normalized):
        raise UnsafeArchiveEntryError(f'Archive entry uses a drive letter: {name!r}.')

    for segment in normalized.split('/'):
        if segment == '..':
            raise UnsafeArchiveEntryError(f'Archive entry escapes the archive root: {name!r}.')

        if not segment or segment == '.':
            continue

        # CON, CON.txt and CON.tar.gz are all the reserved device on Windows
        if segment.split('.')[0].upper() in _WINDOWS_RESERVED_NAMES:
            raise UnsafeArchiveEntryError(f'Archive entry uses a Windows reserved device name: {name!r}.')


def is_regular_file(info: zipfile.ZipInfo) -> bool:
    """True for plain files. Symlinks, FIFOs, sockets and devices are all excluded by the same check."""
    file_type = (info.external_attr >> 16) & _UNIX_FILE_TYPE_MASK
    return file_type in (_UNIX_FILE_TYPE_UNSET, _UNIX_REGULAR_FILE)


class SafeZip:
    """A read-only view over an archive that refuses anything hostile before the caller ever sees it."""

    def __init__(self, zip_file: zipfile.ZipFile, budget: ArchiveBudget, source_name: str) -> None:
        self._zip_file = zip_file
        self._budget = budget
        self._source_name = source_name

    @property
    def limits(self) -> ArchiveLimits:
        return self._budget.limits

    @property
    def source_name(self) -> str:
        return self._source_name

    @classmethod
    def open(
        cls,
        source: Union[str, bytes, IO[bytes]],
        budget: Optional[ArchiveBudget] = None,
        source_name: Optional[str] = None,
    ) -> 'SafeZip':
        """Open a path, a bytes blob, or any binary stream. Pass a shared ``budget`` when recursing."""
        if budget is None:
            budget = ArchiveBudget()

        if isinstance(source, bytes):
            stream: Union[str, IO[bytes]] = io.BytesIO(source)
            name = source_name or '<memory>'
        elif isinstance(source, str):
            stream = source
            name = source_name or os.path.basename(source)
        else:
            stream = source
            name = source_name or '<stream>'

        try:
            zip_file = zipfile.ZipFile(stream)
            entry_count = len(zip_file.infolist())
        except _CORRUPT_ARCHIVE_ERRORS as e:
            raise MalformedArchiveError(f'{name!r} is not a readable archive: {e}') from e

        if entry_count > budget.limits.max_entry_count:
            zip_file.close()
            raise ArchiveEntryCountLimitError(
                f'{name!r} declares {entry_count} entries, past the limit of {budget.limits.max_entry_count}.'
            )

        return cls(zip_file, budget, name)

    # ruff would rather see typing.Self here, but that is 3.11+ and typing_extensions is not a
    # declared dependency of this project
    def __enter__(self) -> 'SafeZip':  # noqa: PYI034
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.close()

    def close(self) -> None:
        self._zip_file.close()

    def entries(self) -> Iterator[SafeZipEntry]:
        """Yield every regular-file entry, in archive order.

        Directories and non-regular entries are skipped silently; an unsafe name aborts the whole archive, because
        an artifact that contains one is not an artifact we are willing to report on.
        """
        try:
            infos = self._zip_file.infolist()
        except _CORRUPT_ARCHIVE_ERRORS as e:
            raise MalformedArchiveError(f'{self._source_name!r} has an unreadable directory: {e}') from e

        for info in infos:
            if info.is_dir():
                continue

            validate_entry_name(info.filename)

            if not is_regular_file(info):
                continue

            yield SafeZipEntry(name=info.filename, size=info.file_size, compress_size=info.compress_size, info=info)

    def read(self, entry: SafeZipEntry, buffer: bool = True) -> EntryContent:
        """Stream one entry, hashing as we go and aborting the moment a ceiling is breached.

        ``buffer=False`` returns digests without holding the bytes, for entries we only need to identify.
        """
        if entry.size > self.limits.max_entry_size_in_bytes:
            raise ArchiveEntrySizeLimitError(
                f'{entry.name!r} declares {entry.size} bytes, past the per-entry limit of '
                f'{self.limits.max_entry_size_in_bytes}.'
            )

        # SHA-1 is identification, not security: it is what artifact indexes key on, and usedforsecurity=False
        # declares that. SHA-256 is computed alongside it so the BOM always carries a strong digest too.
        sha1 = hashlib.sha1(usedforsecurity=False)
        sha256 = hashlib.sha256()
        chunks: Optional[list[bytes]] = [] if buffer else None
        read_bytes = 0

        try:
            # entry.info, never entry.name: see the note on SafeZipEntry.info
            with self._zip_file.open(entry.info if entry.info is not None else entry.name) as handle:
                while True:
                    chunk = handle.read(_READ_CHUNK_SIZE_IN_BYTES)
                    if not chunk:
                        break

                    read_bytes += len(chunk)
                    self._check_entry_size(entry, read_bytes)
                    self._check_compression_ratio(entry, read_bytes)
                    self._budget.consume(len(chunk))

                    sha1.update(chunk)
                    sha256.update(chunk)
                    if chunks is not None:
                        chunks.append(chunk)
        except _CORRUPT_ARCHIVE_ERRORS as e:
            raise MalformedArchiveError(f'{entry.name!r} in {self._source_name!r} could not be read: {e}') from e

        return EntryContent(
            data=b''.join(chunks) if chunks is not None else None,
            sha1=sha1.hexdigest(),
            sha256=sha256.hexdigest(),
            size=read_bytes,
        )

    def _check_entry_size(self, entry: SafeZipEntry, read_bytes: int) -> None:
        if read_bytes > self.limits.max_entry_size_in_bytes:
            raise ArchiveEntrySizeLimitError(
                f'{entry.name!r} expands past the per-entry limit of {self.limits.max_entry_size_in_bytes} bytes.'
            )

    def _check_compression_ratio(self, entry: SafeZipEntry, read_bytes: int) -> None:
        if read_bytes < self.limits.compression_ratio_floor_in_bytes or entry.compress_size <= 0:
            return

        if read_bytes / entry.compress_size > self.limits.max_compression_ratio:
            raise ArchiveCompressionRatioLimitError(
                f'{entry.name!r} expands at more than {self.limits.max_compression_ratio}:1, which is a '
                f'decompression bomb rather than a build artifact.'
            )
