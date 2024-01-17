from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, NamedTuple, Optional, Type

from cycode.cyclient.models import Detection


class Document:
    def __init__(
        self, path: str, content: str, is_git_diff_format: bool = False, unique_id: Optional[str] = None
    ) -> None:
        self.path = path
        self.content = content
        self.is_git_diff_format = is_git_diff_format
        self.unique_id = unique_id

    def __repr__(self) -> str:
        return 'path:{0}, content:{1}'.format(self.path, self.content)


class DocumentDetections:
    def __init__(self, document: Document, detections: List[Detection]) -> None:
        self.document = document
        self.detections = detections

    def __repr__(self) -> str:
        return 'document:{0}, detections:{1}'.format(self.document, self.detections)


class Severity(Enum):
    INFO = -1
    LOW = 0
    MEDIUM = 1
    MODERATE = 1  # noqa: PIE796. TODO(MarshalX): rework. should not be Enum
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


class LocalScanResult(NamedTuple):
    scan_id: str
    report_url: Optional[str]
    document_detections: List[DocumentDetections]
    issue_detected: bool
    detections_count: int
    relevant_detections_count: int


@dataclass
class ResourceChange:
    resource_type: str
    name: str
    actions: List[str]
    values: Dict[str, str]

    def __repr__(self) -> str:
        return f'resource_type: {self.resource_type}, name: {self.name}'
