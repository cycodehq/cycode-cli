from collections import defaultdict
from typing import TYPE_CHECKING

from cycode.cli.cli_types import SeverityOption

if TYPE_CHECKING:
    from cycode.cyclient.models import Detection


def __group_by(detections: list['Detection'], details_field_name: str) -> dict[str, list['Detection']]:
    grouped = defaultdict(list)
    for detection in detections:
        grouped[detection.detection_details.get(details_field_name)].append(detection)
    return grouped


def __severity_sort_key(detection: 'Detection') -> int:
    severity = detection.severity if detection.severity else 'unknown'
    return SeverityOption.get_member_weight(severity)


def _sort_detections_by_severity(detections: list['Detection']) -> list['Detection']:
    return sorted(detections, key=__severity_sort_key, reverse=True)


def __package_sort_key(detection: 'Detection') -> int:
    return detection.detection_details.get('package_name')


def _sort_detections_by_package(detections: list['Detection']) -> list['Detection']:
    return sorted(detections, key=__package_sort_key)


def sort_and_group_detections(detections: list['Detection']) -> tuple[list['Detection'], set[int]]:
    """Sort detections by severity and group by repository, code project and package name.

    Note:
        Code Project is path to the manifest file.

        Grouping by code projects also groups by ecosystem.
        Because manifest files are unique per ecosystem.

    """
    resulting_detections = []
    group_separator_indexes = set()

    # we sort detections by package name to make persist output order
    sorted_detections = _sort_detections_by_package(detections)

    grouped_by_repository = __group_by(sorted_detections, 'repository_name')
    for repository_group in grouped_by_repository.values():
        grouped_by_code_project = __group_by(repository_group, 'file_name')
        for code_project_group in grouped_by_code_project.values():
            grouped_by_package = __group_by(code_project_group, 'package_name')
            for package_group in grouped_by_package.values():
                group_separator_indexes.add(len(resulting_detections) - 1)  # indexing starts from 0
                resulting_detections.extend(_sort_detections_by_severity(package_group))

    return resulting_detections, group_separator_indexes
