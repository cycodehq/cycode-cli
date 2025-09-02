import os
from abc import ABC, abstractmethod
from collections.abc import Hashable
from typing import Any

from cycode.cli.utils.yaml_utils import read_yaml_file, update_yaml_file
from cycode.logger import get_logger

logger = get_logger('Base File Manager')


class BaseFileManager(ABC):
    @abstractmethod
    def get_filename(self) -> str: ...

    def read_file(self) -> dict[Hashable, Any]:
        return read_yaml_file(self.get_filename())

    def write_content_to_file(self, content: dict[Hashable, Any]) -> None:
        filename = self.get_filename()

        try:
            os.makedirs(os.path.dirname(filename), exist_ok=True)
        except Exception as e:
            logger.warning('Failed to create directory for file, %s', {'filename': filename}, exc_info=e)
            return

        update_yaml_file(filename, content)
