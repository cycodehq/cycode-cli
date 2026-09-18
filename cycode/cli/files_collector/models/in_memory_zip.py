import shutil
import tempfile
from collections import defaultdict
from os import SEEK_END
from pathlib import Path
from typing import IO, Optional
from zipfile import ZIP_DEFLATED, ZipFile

from cycode.cli import consts
from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.utils.host_info import is_64bit
from cycode.cli.utils.path_utils import concat_unique_id
from cycode.logger import get_logger

logger = get_logger('ZIP')

_SPOOL_DIRECTORY_NAME = 'tmp'


def _get_spool_directory(configuration_manager: ConfigurationManager) -> Optional[str]:
    """Directory to spill big ZIPs into. None falls back to the system temp directory."""
    try:
        directory = Path(configuration_manager.global_config_file_manager.get_config_directory_path())
        spool_directory = directory / _SPOOL_DIRECTORY_NAME
        spool_directory.mkdir(parents=True, exist_ok=True)
        return str(spool_directory)
    except OSError as e:
        logger.debug('Failed to create the spool directory; falling back to the system one', exc_info=e)
        return None


class InMemoryZip:
    def __init__(self) -> None:
        self.configuration_manager = ConfigurationManager()

        self._spool_max_size = consts.ZIP_SPOOL_MAX_SIZE_IN_BYTES
        self._buffer = tempfile.SpooledTemporaryFile(  # noqa: SIM115  # closed by cleanup(), lives past close()
            max_size=self._spool_max_size,
            dir=_get_spool_directory(self.configuration_manager),
        )

        # ZIP64 lifts the 65,535 entries and 4 GiB caps of the original ZIP format.
        # It requires 64-bit offsets, so we only enable it on a 64-bit interpreter.
        self._allow_zip64 = is_64bit()
        self.zip = ZipFile(self._buffer, mode='a', compression=ZIP_DEFLATED, allowZip64=self._allow_zip64)

        self._files_count = 0
        self._extension_statistics = defaultdict(int)

    def append(self, filename: str, unique_id: Optional[str], content: str) -> None:
        self._files_count += 1
        self._extension_statistics[Path(filename).suffix] += 1

        if unique_id:
            filename = concat_unique_id(filename, unique_id)

        # Encode content to bytes with error handling to handle surrogate characters
        # that cannot be encoded to UTF-8. Use 'replace' to replace invalid characters
        # with the Unicode replacement character (U+FFFD).
        content_bytes = content.encode('utf-8', errors='replace')
        self.zip.writestr(filename, content_bytes)

    def close(self) -> None:
        self.zip.close()

    def cleanup(self) -> None:
        """Release the buffer, deleting the spilled temp file if there is one."""
        self._buffer.close()

    def __enter__(self) -> 'InMemoryZip':  # noqa: PYI034  # typing.Self needs Python 3.11
        return self

    def __exit__(self, *_: object) -> None:
        self.cleanup()

    def stream(self) -> IO[bytes]:
        """The whole archive as a file object, rewound. Doesn't copy it into memory.

        Note: before Python 3.11 SpooledTemporaryFile isn't a real IOBase, so the returned object
        has no seekable()/readable()/writable(). read/seek/tell work on every supported version.
        """
        self._buffer.seek(0)
        return self._buffer

    def read(self) -> bytes:
        self._buffer.seek(0)
        return self._buffer.read()

    def write_on_disk(self, path: 'Path') -> None:
        with open(path, 'wb') as f:
            shutil.copyfileobj(self.stream(), f)

    @property
    def size(self) -> int:
        position = self._buffer.tell()
        try:
            self._buffer.seek(0, SEEK_END)
            return self._buffer.tell()
        finally:
            self._buffer.seek(position)

    @property
    def is_rolled_over(self) -> bool:
        """Whether the archive outgrew the threshold and moved from memory to the disk.

        SpooledTemporaryFile spills on the write that crosses max_size, and the archive only grows,
        so the size says it without reaching into the private _rolled flag.
        """
        return self.size > self._spool_max_size

    @property
    def allow_zip64(self) -> bool:
        return self._allow_zip64

    @property
    def files_count(self) -> int:
        return self._files_count

    @property
    def extension_statistics(self) -> dict[str, int]:
        return dict(self._extension_statistics)
