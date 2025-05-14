import os
from abc import ABC, abstractmethod
from collections.abc import Hashable
from typing import Any

from cycode.cli.utils.yaml_utils import read_yaml_file, update_yaml_file


class BaseFileManager(ABC):
    @abstractmethod
    def get_filename(self) -> str: ...

    def read_file(self) -> dict[Hashable, Any]:
        return read_yaml_file(self.get_filename())

    def write_content_to_file(self, content: dict[Hashable, Any]) -> None:
        filename = self.get_filename()
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        update_yaml_file(filename, content)
