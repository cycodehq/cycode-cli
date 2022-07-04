import os
from abc import ABC, abstractmethod
from cli.utils.yaml_utils import update_file, read_file


class BaseFileManager(ABC):

    @abstractmethod
    def get_filename(self):
        pass

    def read_file(self):
        try:
            return read_file(self.get_filename())
        except FileNotFoundError:
            return {}

    def write_content_to_file(self, content):
        filename = self.get_filename()
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        update_file(filename, content)
