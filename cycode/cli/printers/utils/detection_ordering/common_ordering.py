from collections import defaultdict
from typing import TYPE_CHECKING, List, Set, Tuple

from cycode.cli.cli_types import SeverityOption

if TYPE_CHECKING:
    from cycode.cli.models import Document, LocalScanResult
    from cycode.cyclient.models import Detection


GroupedDetections = Tuple[List[Tuple['Detection', 'Document']], Set[int]]


def __severity_sort_key(detection_with_document: Tuple['Detection', 'Document']) -> int:
    detection, _ = detection_with_document
    severity = detection.severity if detection.severity else ''
    return SeverityOption.get_member_weight(severity)


def _sort_detections_by_severity(
    detections_with_documents: List[Tuple['Detection', 'Document']],
) -> List[Tuple['Detection', 'Document']]:
    return sorted(detections_with_documents, key=__severity_sort_key, reverse=True)


def __file_path_sort_key(detection_with_document: Tuple['Detection', 'Document']) -> str:
    _, document = detection_with_document
    return document.path


def _sort_detections_by_file_path(
    detections_with_documents: List[Tuple['Detection', 'Document']],
) -> List[Tuple['Detection', 'Document']]:
    return sorted(detections_with_documents, key=__file_path_sort_key)


def sort_and_group_detections(
    detections_with_documents: List[Tuple['Detection', 'Document']],
) -> GroupedDetections:
    """Sort detections by severity and group by file name."""
    detections = []
    group_separator_indexes = set()

    # we sort detections by file path to make persist output order
    sorted_detections = _sort_detections_by_file_path(detections_with_documents)

    grouped_by_file_path = defaultdict(list)
    for detection, document in sorted_detections:
        grouped_by_file_path[document.path].append((detection, document))

    for file_path_group in grouped_by_file_path.values():
        group_separator_indexes.add(len(detections) - 1)  # indexing starts from 0
        detections.extend(_sort_detections_by_severity(file_path_group))

    return detections, group_separator_indexes


def sort_and_group_detections_from_scan_result(local_scan_results: List['LocalScanResult']) -> GroupedDetections:
    detections_with_documents = []
    for local_scan_result in local_scan_results:
        for document_detections in local_scan_result.document_detections:
            detections_with_documents.extend(
                [(detection, document_detections.document) for detection in document_detections.detections]
            )

    return sort_and_group_detections(detections_with_documents)
