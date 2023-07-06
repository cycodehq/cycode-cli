import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Hashable

from cycode.cli.utils.yaml_utils import read_file, update_file


class BaseFileManager(ABC):
    @abstractmethod
    def get_filename(self) -> str:
        ...

    def read_file(self) -> Dict[Hashable, Any]:
        try:
            return read_file(self.get_filename())
        except FileNotFoundError:
            return {}

    def write_content_to_file(self, content: Dict[Hashable, Any]) -> None:
        filename = self.get_filename()
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        update_file(filename, content)
