import os
import pathlib
import re
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
        return click.confirm(f'File {self._file_path} already exists. Save with a different filename?', default=True)

    def _write(self, content: str) -> None:
        with open(self._file_path, 'w', encoding='UTF-8') as f:
            f.write(content)

    def _notify_about_saved_file(self) -> None:
        click.echo(f'Report saved to {self._file_path}')

    def _find_and_set_unique_filename(self) -> None:
        attempt_no = 0
        while self.is_exists():
            attempt_no += 1

            base, ext = os.path.splitext(self._file_path)
            # Remove previous suffix
            base = re.sub(r'-\d+$', '', base)

            self._file_path = pathlib.Path(f'{base}-{attempt_no}{ext}')

    def write(self, content: str) -> None:
        if self.is_exists() and self._prompt_overwrite():
            self._find_and_set_unique_filename()

        self._write(content)
        self._notify_about_saved_file()
