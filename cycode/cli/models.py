from dataclasses import dataclass
from typing import NamedTuple, Optional

from cycode.cyclient.models import Detection


class Document:
    def __init__(
        self,
        path: str,
        content: str,
        is_git_diff_format: bool = False,
        unique_id: Optional[str] = None,
        absolute_path: Optional[str] = None,
    ) -> None:
        self.path = path
        self.content = content
        self.is_git_diff_format = is_git_diff_format
        self.unique_id = unique_id
        self.absolute_path = absolute_path

    def __repr__(self) -> str:
        return f'path:{self.path}, content:{self.content}'


class DocumentDetections:
    def __init__(self, document: Document, detections: list[Detection]) -> None:
        self.document = document
        self.detections = detections

    def __repr__(self) -> str:
        return f'document:{self.document}, detections:{self.detections}'


class CliError(NamedTuple):
    code: str
    message: str
    soft_fail: bool = False

    def enrich(self, additional_message: str) -> 'CliError':
        message = f'{self.message} ({additional_message})'
        return CliError(self.code, message, self.soft_fail)


CliErrors = dict[type[BaseException], CliError]


class CliResult(NamedTuple):
    success: bool
    message: str
    data: Optional[dict[str, any]] = None


class LocalScanResult(NamedTuple):
    scan_id: str
    report_url: Optional[str]
    document_detections: list[DocumentDetections]
    issue_detected: bool
    detections_count: int
    relevant_detections_count: int


@dataclass
class ResourceChange:
    module_address: Optional[str]
    resource_type: str
    name: str
    index: Optional[int]
    actions: list[str]
    values: dict[str, str]

    def __repr__(self) -> str:
        return f'resource_type: {self.resource_type}, name: {self.name}'
