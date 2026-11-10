from dataclasses import dataclass
from typing import NamedTuple

from cycode.cyclient.models import Detection


class Document:
    def __init__(
        self,
        path: str,
        content: str | bytes,
        is_git_diff_format: bool = False,
        unique_id: str | None = None,
        absolute_path: str | None = None,
    ) -> None:
        self.path = path
        # bytes for binary content scanned as is (an image attached to an AI prompt); text otherwise
        self.content = content
        self.is_git_diff_format = is_git_diff_format
        self.unique_id = unique_id
        self.absolute_path = absolute_path

    @property
    def text_content(self) -> str:
        """The content as text; '' for binary content.

        The server reads the text out of binary content (OCR of an image) and reports positions into that text,
        which never exists locally, so there is no line or value to cut out of it here.
        """
        return self.content if isinstance(self.content, str) else ''

    def __repr__(self) -> str:
        content = f'<{len(self.content)} bytes>' if isinstance(self.content, bytes) else self.content
        return f'path:{self.path}, content:{content}'


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
    data: dict[str, any] | None = None


class LocalScanResult(NamedTuple):
    scan_id: str
    report_url: str | None
    document_detections: list[DocumentDetections]
    issue_detected: bool
    detections_count: int
    relevant_detections_count: int
    verdict: str | None = None


@dataclass
class ResourceChange:
    module_address: str | None
    resource_type: str
    name: str
    index: int | None
    actions: list[str]
    values: dict[str, str]

    def __repr__(self) -> str:
        return f'resource_type: {self.resource_type}, name: {self.name}'
