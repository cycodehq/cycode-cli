import pathlib
from typing import Optional

import click


class SbomReportFile:
    def __init__(self, storage_path: str, output_format: str, output_file: Optional[pathlib.Path]) -> None:
        if output_file is None:
            output_file = pathlib.Path(storage_path)

        output_ext = f'.{output_format}'
        if output_file.suffix != output_ext:
            output_file = output_file.with_suffix(output_ext)

        self._file_path = output_file

    def is_exists(self) -> bool:
        return self._file_path.exists()

    def _prompt_overwrite(self) -> bool:
        return click.confirm(f'File {self._file_path} already exists. Overwrite?')

    def _write(self, content: str) -> None:
        with open(self._file_path, 'w', encoding='UTF-8') as f:
            f.write(content)

    def write(self, content: str) -> None:
        if self.is_exists() and not self._prompt_overwrite():
            return

        self._write(content)
