from collections import defaultdict
from io import BytesIO
from pathlib import Path
from sys import getsizeof
from typing import Optional
from zipfile import ZIP_DEFLATED, ZipFile

from cycode.cli.user_settings.configuration_manager import ConfigurationManager
from cycode.cli.utils.path_utils import concat_unique_id


class InMemoryZip:
    def __init__(self) -> None:
        self.configuration_manager = ConfigurationManager()

        self.in_memory_zip = BytesIO()
        self.zip = ZipFile(self.in_memory_zip, mode='a', compression=ZIP_DEFLATED, allowZip64=False)

        self._files_count = 0
        self._extension_statistics = defaultdict(int)

    def append(self, filename: str, unique_id: Optional[str], content: str) -> None:
        self._files_count += 1
        self._extension_statistics[Path(filename).suffix] += 1

        if unique_id:
            filename = concat_unique_id(filename, unique_id)

        self.zip.writestr(filename, content)

    def close(self) -> None:
        self.zip.close()

    def read(self) -> bytes:
        self.in_memory_zip.seek(0)
        return self.in_memory_zip.read()

    def write_on_disk(self, path: 'Path') -> None:
        with open(path, 'wb') as f:
            f.write(self.read())

    @property
    def size(self) -> int:
        return getsizeof(self.in_memory_zip)

    @property
    def files_count(self) -> int:
        return self._files_count

    @property
    def extension_statistics(self) -> dict[str, int]:
        return dict(self._extension_statistics)
