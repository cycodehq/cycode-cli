from enum import Enum
from typing import List, NamedTuple, Dict, Type

from cycode.cyclient.models import Detection


class Document:
    def __init__(self, path: str, content: str, is_git_diff_format: bool = False, unique_id: str = None):
        self.path = path
        self.content = content
        self.is_git_diff_format = is_git_diff_format
        self.unique_id = unique_id

    def __repr__(self) -> str:
        return (
            "path:{0}, "
            "content:{1}".format(self.path, self.content)
        )


class DocumentDetections:
    def __init__(self, document: Document, detections: List[Detection]):
        self.document = document
        self.detections = detections

    def __repr__(self) -> str:
        return (
            "document:{0}, "
            "detections:{1}".format(self.document, self.detections)
        )


class Severity(Enum):
    INFO = -1
    LOW = 0
    MEDIUM = 1
    MODERATE = 1
    HIGH = 2
    CRITICAL = 3

    @staticmethod
    def try_get_value(name: str) -> any:
        if name not in Severity.__members__:
            return None

        return Severity[name].value


class CliError(NamedTuple):
    code: str
    message: str
    soft_fail: bool = False


CliErrors = Dict[Type[Exception], CliError]


class CliResult(NamedTuple):
    success: bool
    message: str
