from typing import TYPE_CHECKING

from cycode.cli.cli_types import SeverityOption

if TYPE_CHECKING:
    from cycode.cli.models import Document, LocalScanResult
    from cycode.cyclient.models import Detection


GroupedDetections = tuple[list[tuple['Detection', 'Document']], set[int]]


def __severity_sort_key(detection_with_document: tuple['Detection', 'Document']) -> int:
    detection, _ = detection_with_document
    severity = detection.severity if detection.severity else ''
    return SeverityOption.get_member_weight(severity)


def _sort_detections_by_severity(
    detections_with_documents: list[tuple['Detection', 'Document']],
) -> list[tuple['Detection', 'Document']]:
    return sorted(detections_with_documents, key=__severity_sort_key, reverse=True)


def __file_path_sort_key(detection_with_document: tuple['Detection', 'Document']) -> str:
    _, document = detection_with_document
    return document.path


def _sort_detections_by_file_path(
    detections_with_documents: list[tuple['Detection', 'Document']],
) -> list[tuple['Detection', 'Document']]:
    return sorted(detections_with_documents, key=__file_path_sort_key)


def sort_and_group_detections(
    detections_with_documents: list[tuple['Detection', 'Document']],
) -> GroupedDetections:
    """Sort detections by severity. We do not have grouping here (don't find the best one yet)."""
    group_separator_indexes = set()

    # we sort detections by file path to make persist output order
    sorted_by_path_detections = _sort_detections_by_file_path(detections_with_documents)
    sorted_by_severity = _sort_detections_by_severity(sorted_by_path_detections)

    return sorted_by_severity, group_separator_indexes


def sort_and_group_detections_from_scan_result(local_scan_results: list['LocalScanResult']) -> GroupedDetections:
    detections_with_documents = []
    for local_scan_result in local_scan_results:
        for document_detections in local_scan_result.document_detections:
            detections_with_documents.extend(
                [(detection, document_detections.document) for detection in document_detections.detections]
            )

    return sort_and_group_detections(detections_with_documents)
