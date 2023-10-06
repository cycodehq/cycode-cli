from io import BytesIO
from sys import getsizeof
from typing import Optional
from zipfile import ZIP_DEFLATED, ZipFile

from cycode.cli.utils.path_utils import concat_unique_id


class InMemoryZip(object):
    def __init__(self) -> None:
        # Create the in-memory file-like object
        self.in_memory_zip = BytesIO()
        self.zip = ZipFile(self.in_memory_zip, 'a', ZIP_DEFLATED, False)

    def append(self, filename: str, unique_id: Optional[str], content: str) -> None:
        # Write the file to the in-memory zip
        if unique_id:
            filename = concat_unique_id(filename, unique_id)

        self.zip.writestr(filename, content)

    def close(self) -> None:
        self.zip.close()

    # to bytes
    def read(self) -> bytes:
        self.in_memory_zip.seek(0)
        return self.in_memory_zip.read()

    @property
    def size(self) -> int:
        return getsizeof(self.in_memory_zip)
