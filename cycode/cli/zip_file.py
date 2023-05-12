import os.path
from zipfile import ZipFile, ZIP_DEFLATED
from io import BytesIO


class InMemoryZip(object):
    def __init__(self):
        # Create the in-memory file-like object
        self.in_memory_zip = BytesIO()
        self.zip = ZipFile(self.in_memory_zip, "a", ZIP_DEFLATED, False)

    def append(self, filename, unique_id, content):
        # Write the file to the in-memory zip
        filename = filename if unique_id is None else concat_unique_id(filename, unique_id)
        self.zip.writestr(filename, content)

    def close(self):
        self.zip.close()

    # to bytes
    def read(self) -> bytes:
        self.in_memory_zip.seek(0)
        return self.in_memory_zip.read()


def concat_unique_id(filename: str, unique_id: str) -> str:
    return f'{unique_id}{filename}' if filename.startswith(os.sep) else os.path.join(unique_id, filename)
