import os
from typing import TYPE_CHECKING, Optional

import typer

from cycode.cli import consts
from cycode.cli.apps.scan.aggregation_report import try_get_aggregation_report_url_if_needed
from cycode.cli.apps.scan.detection_excluder import exclude_irrelevant_document_detections
from cycode.cli.models import Document, DocumentDetections, LocalScanResult
from cycode.cli.utils.path_utils import get_path_by_os, normalize_file_path
from cycode.cyclient.models import (
    Detection,
    DetectionSchema,
    DetectionsPerFile,
    ScanResultsSyncFlow,
    ZippedFileScanResult,
)
from cycode.logger import get_logger

if TYPE_CHECKING:
    from cycode.cli.models import CliError
    from cycode.cyclient.models import ScanDetailsResponse
    from cycode.cyclient.scan_client import ScanClient

logger = get_logger('Scan Results')


def _get_document_by_file_name(
    documents: list[Document], file_name: str, unique_id: Optional[str] = None
) -> Optional[Document]:
    for document in documents:
        if normalize_file_path(document.path) == normalize_file_path(file_name) and document.unique_id == unique_id:
            return document

    return None


def _get_document_detections(
    scan_result: ZippedFileScanResult, documents_to_scan: list[Document]
) -> list[DocumentDetections]:
    logger.debug('Getting document detections')

    document_detections = []
    for detections_per_file in scan_result.detections_per_file:
        file_name = get_path_by_os(detections_per_file.file_name)
        commit_id = detections_per_file.commit_id

        logger.debug(
            'Going to find the document of the violated file, %s', {'file_name': file_name, 'commit_id': commit_id}
        )

        document = _get_document_by_file_name(documents_to_scan, file_name, commit_id)
        document_detections.append(DocumentDetections(document=document, detections=detections_per_file.detections))

    return document_detections


def create_local_scan_result(
    scan_result: ZippedFileScanResult,
    documents_to_scan: list[Document],
    command_scan_type: str,
    scan_type: str,
    severity_threshold: str,
) -> LocalScanResult:
    document_detections = _get_document_detections(scan_result, documents_to_scan)
    relevant_document_detections_list = exclude_irrelevant_document_detections(
        document_detections, scan_type, command_scan_type, severity_threshold
    )

    detections_count = sum([len(document_detection.detections) for document_detection in document_detections])
    relevant_detections_count = sum(
        [len(document_detections.detections) for document_detections in relevant_document_detections_list]
    )

    return LocalScanResult(
        scan_id=scan_result.scan_id,
        report_url=scan_result.report_url,
        document_detections=relevant_document_detections_list,
        issue_detected=len(relevant_document_detections_list) > 0,
        detections_count=detections_count,
        relevant_detections_count=relevant_detections_count,
    )


def _get_file_name_from_detection(scan_type: str, raw_detection: dict) -> str:
    if scan_type == consts.SAST_SCAN_TYPE:
        return raw_detection['detection_details']['file_path']
    if scan_type == consts.SECRET_SCAN_TYPE:
        return _get_secret_file_name_from_detection(raw_detection)

    return raw_detection['detection_details']['file_name']


def _get_secret_file_name_from_detection(raw_detection: dict) -> str:
    file_path: str = raw_detection['detection_details']['file_path']
    file_name: str = raw_detection['detection_details']['file_name']
    return os.path.join(file_path, file_name)


def _map_detections_per_file_and_commit_id(scan_type: str, raw_detections: list[dict]) -> list[DetectionsPerFile]:
    """Convert a list of detections (async flow) to list of DetectionsPerFile objects (sync flow).

    Args:
        scan_type: Type of the scan.
        raw_detections: List of detections as is returned from the server.

    Note:
        This method fakes server response structure
        to be able to use the same logic for both async and sync scans.

    Note:
        Aggregation is performed by file name and commit ID (if available)

    """
    detections_per_files = {}
    for raw_detection in raw_detections:
        try:
            # FIXME(MarshalX): investigate this field mapping
            raw_detection['message'] = raw_detection['correlation_message']

            file_name = _get_file_name_from_detection(scan_type, raw_detection)
            detection: Detection = DetectionSchema().load(raw_detection)
            commit_id: Optional[str] = detection.detection_details.get('commit_id')  # could be None
            group_by_key = (file_name, commit_id)

            if group_by_key in detections_per_files:
                detections_per_files[group_by_key].append(detection)
            else:
                detections_per_files[group_by_key] = [detection]
        except Exception as e:
            logger.debug('Failed to parse detection', exc_info=e)
            continue

    return [
        DetectionsPerFile(file_name=file_name, detections=file_detections, commit_id=commit_id)
        for (file_name, commit_id), file_detections in detections_per_files.items()
    ]


def init_default_scan_result(scan_id: str) -> ZippedFileScanResult:
    return ZippedFileScanResult(
        did_detect=False,
        detections_per_file=[],
        scan_id=scan_id,
    )


def get_scan_result(
    cycode_client: 'ScanClient',
    scan_type: str,
    scan_id: str,
    scan_details: 'ScanDetailsResponse',
    scan_parameters: dict,
) -> ZippedFileScanResult:
    if not scan_details.detections_count:
        return init_default_scan_result(scan_id)

    scan_raw_detections = cycode_client.get_scan_raw_detections(scan_id)

    return ZippedFileScanResult(
        did_detect=True,
        detections_per_file=_map_detections_per_file_and_commit_id(scan_type, scan_raw_detections),
        scan_id=scan_id,
        report_url=try_get_aggregation_report_url_if_needed(scan_parameters, cycode_client, scan_type),
    )


def get_sync_scan_result(scan_type: str, scan_results: 'ScanResultsSyncFlow') -> ZippedFileScanResult:
    return ZippedFileScanResult(
        did_detect=True,
        detections_per_file=_map_detections_per_file_and_commit_id(scan_type, scan_results.detection_messages),
        scan_id=scan_results.id,
    )


def print_local_scan_results(
    ctx: typer.Context, local_scan_results: list[LocalScanResult], errors: Optional[dict[str, 'CliError']] = None
) -> None:
    printer = ctx.obj.get('console_printer')
    printer.update_ctx(ctx)
    printer.print_scan_results(local_scan_results, errors)


def enrich_scan_result_with_data_from_detection_rules(
    cycode_client: 'ScanClient', scan_result: ZippedFileScanResult
) -> None:
    detection_rule_ids = set()
    for detections_per_file in scan_result.detections_per_file:
        for detection in detections_per_file.detections:
            detection_rule_ids.add(detection.detection_rule_id)

    detection_rules = cycode_client.get_detection_rules(detection_rule_ids)
    detection_rules_by_id = {detection_rule.detection_rule_id: detection_rule for detection_rule in detection_rules}

    for detections_per_file in scan_result.detections_per_file:
        for detection in detections_per_file.detections:
            detection_rule = detection_rules_by_id.get(detection.detection_rule_id)
            if not detection_rule:
                # we want to make sure that BE returned it. better to not map data instead of failed scan
                continue

            if not detection.severity and detection_rule.classification_data:
                # it's fine to take the first one, because:
                # - for "secrets" and "iac" there is only one classification rule per-detection rule
                # - for "sca" and "sast" we get severity from detection service
                detection.severity = detection_rule.classification_data[0].severity

            # detection_details never was typed properly. so not a problem for now
            detection.detection_details['custom_remediation_guidelines'] = detection_rule.custom_remediation_guidelines
            detection.detection_details['remediation_guidelines'] = detection_rule.remediation_guidelines
            detection.detection_details['description'] = detection_rule.description
            detection.detection_details['policy_display_name'] = detection_rule.display_name
