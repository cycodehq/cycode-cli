from typing import Optional

from cycode.cli import consts
from cycode.cli.cli_types import SeverityOption
from cycode.cli.config import configuration_manager
from cycode.cli.models import DocumentDetections
from cycode.cyclient.models import Detection
from cycode.logger import get_logger

logger = get_logger('Detection Excluder')


def _does_severity_match_severity_threshold(severity: str, severity_threshold: str) -> bool:
    detection_severity_value = SeverityOption.get_member_weight(severity)
    severity_threshold_value = SeverityOption.get_member_weight(severity_threshold)
    if detection_severity_value < 0 or severity_threshold_value < 0:
        return True

    return detection_severity_value >= severity_threshold_value


def _exclude_irrelevant_detections(
    detections: list[Detection], scan_type: str, command_scan_type: str, severity_threshold: str
) -> list[Detection]:
    relevant_detections = _exclude_detections_by_exclusions_configuration(detections, scan_type)
    relevant_detections = _exclude_detections_by_scan_type(relevant_detections, scan_type, command_scan_type)
    return _exclude_detections_by_severity(relevant_detections, severity_threshold)


def _exclude_detections_by_severity(detections: list[Detection], severity_threshold: str) -> list[Detection]:
    relevant_detections = []
    for detection in detections:
        severity = detection.severity

        if _does_severity_match_severity_threshold(severity, severity_threshold):
            relevant_detections.append(detection)
        else:
            logger.debug(
                'Going to ignore violations because they are below the severity threshold, %s',
                {'severity': severity, 'severity_threshold': severity_threshold},
            )

    return relevant_detections


def _exclude_detections_by_scan_type(
    detections: list[Detection], scan_type: str, command_scan_type: str
) -> list[Detection]:
    if command_scan_type == consts.PRE_COMMIT_COMMAND_SCAN_TYPE:
        return _exclude_detections_in_deleted_lines(detections)

    exclude_in_deleted_lines = configuration_manager.get_should_exclude_detections_in_deleted_lines(command_scan_type)
    if (
        command_scan_type in consts.COMMIT_RANGE_BASED_COMMAND_SCAN_TYPES
        and scan_type == consts.SECRET_SCAN_TYPE
        and exclude_in_deleted_lines
    ):
        return _exclude_detections_in_deleted_lines(detections)

    return detections


def _exclude_detections_in_deleted_lines(detections: list[Detection]) -> list[Detection]:
    return [detection for detection in detections if detection.detection_details.get('line_type') != 'Removed']


def _exclude_detections_by_exclusions_configuration(detections: list[Detection], scan_type: str) -> list[Detection]:
    exclusions = configuration_manager.get_exclusions_by_scan_type(scan_type)
    return [detection for detection in detections if not _should_exclude_detection(detection, exclusions)]


def _should_exclude_detection(detection: Detection, exclusions: dict) -> bool:
    # FIXME(MarshalX): what the difference between by_value and by_sha?
    exclusions_by_value = exclusions.get(consts.EXCLUSIONS_BY_VALUE_SECTION_NAME, [])
    if _is_detection_sha_configured_in_exclusions(detection, exclusions_by_value):
        logger.debug(
            'Ignoring violation because its value is on the ignore list, %s',
            {'value_sha': detection.detection_details.get('sha512')},
        )
        return True

    exclusions_by_sha = exclusions.get(consts.EXCLUSIONS_BY_SHA_SECTION_NAME, [])
    if _is_detection_sha_configured_in_exclusions(detection, exclusions_by_sha):
        logger.debug(
            'Ignoring violation because its SHA value is on the ignore list, %s',
            {'sha': detection.detection_details.get('sha512')},
        )
        return True

    exclusions_by_rule = exclusions.get(consts.EXCLUSIONS_BY_RULE_SECTION_NAME, [])
    detection_rule_id = detection.detection_rule_id
    if detection_rule_id in exclusions_by_rule:
        logger.debug(
            'Ignoring violation because its Detection Rule ID is on the ignore list, %s',
            {'detection_rule_id': detection_rule_id},
        )
        return True

    exclusions_by_package = exclusions.get(consts.EXCLUSIONS_BY_PACKAGE_SECTION_NAME, [])
    package = _get_package_name(detection)
    if package and package in exclusions_by_package:
        logger.debug('Ignoring violation because its package@version is on the ignore list, %s', {'package': package})
        return True

    exclusions_by_cve = exclusions.get(consts.EXCLUSIONS_BY_CVE_SECTION_NAME, [])
    cve = _get_cve_identifier(detection)
    if cve and cve in exclusions_by_cve:
        logger.debug('Ignoring violation because its CVE is on the ignore list, %s', {'cve': cve})
        return True

    return False


def _is_detection_sha_configured_in_exclusions(detection: Detection, exclusions: list[str]) -> bool:
    detection_sha = detection.detection_details.get('sha512')
    return detection_sha in exclusions


def _get_package_name(detection: Detection) -> Optional[str]:
    package_name = detection.detection_details.get('vulnerable_component')
    package_version = detection.detection_details.get('vulnerable_component_version')

    if package_name is None:
        package_name = detection.detection_details.get('package_name')
        package_version = detection.detection_details.get('package_version')

    if package_name and package_version:
        return f'{package_name}@{package_version}'

    return None


def _get_cve_identifier(detection: Detection) -> Optional[str]:
    return detection.detection_details.get('alert', {}).get('cve_identifier')


def exclude_irrelevant_document_detections(
    document_detections_list: list[DocumentDetections],
    scan_type: str,
    command_scan_type: str,
    severity_threshold: str,
) -> list[DocumentDetections]:
    relevant_document_detections_list = []
    for document_detections in document_detections_list:
        relevant_detections = _exclude_irrelevant_detections(
            document_detections.detections, scan_type, command_scan_type, severity_threshold
        )
        if relevant_detections:
            relevant_document_detections_list.append(
                DocumentDetections(document=document_detections.document, detections=relevant_detections)
            )

    return relevant_document_detections_list
