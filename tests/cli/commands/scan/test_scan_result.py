import os
from unittest.mock import Mock

from cycode.cli.apps.scan.scan_result import _get_document_detections, _get_file_name_from_detection
from cycode.cli.consts import IAC_SCAN_TYPE, SAST_SCAN_TYPE, SCA_SCAN_TYPE, SECRET_SCAN_TYPE
from cycode.cli.models import Document
from cycode.cli.utils.path_utils import concat_unique_id
from cycode.cyclient.models import DetectionsPerFile, ZippedFileScanResult


def test_get_file_name_from_detection_sca_uses_file_path() -> None:
    raw_detection = {
        'detection_details': {
            'file_name': 'package.json',
            'file_path': '/repo/path/package.json',
        },
    }
    result = _get_file_name_from_detection(SCA_SCAN_TYPE, raw_detection)
    assert result == '/repo/path/package.json'


def test_get_file_name_from_detection_iac_uses_file_path() -> None:
    raw_detection = {
        'detection_details': {
            'file_name': 'main.tf',
            'file_path': '/repo/infra/main.tf',
        },
    }
    result = _get_file_name_from_detection(IAC_SCAN_TYPE, raw_detection)
    assert result == '/repo/infra/main.tf'


def test_get_file_name_from_detection_sast_uses_file_path() -> None:
    raw_detection = {
        'detection_details': {
            'file_path': '/repo/src/app.py',
        },
    }
    result = _get_file_name_from_detection(SAST_SCAN_TYPE, raw_detection)
    assert result == '/repo/src/app.py'


def test_get_file_name_from_detection_secret_uses_file_path_and_file_name() -> None:
    raw_detection = {
        'detection_details': {
            'file_path': '/repo/src',
            'file_name': '.env',
        },
    }
    result = _get_file_name_from_detection(SECRET_SCAN_TYPE, raw_detection)
    assert result == os.path.join('/repo/src', '.env')


def _scan_result_for(file_name: str, commit_id: str) -> ZippedFileScanResult:
    return ZippedFileScanResult(
        did_detect=True,
        detections_per_file=[DetectionsPerFile(file_name=file_name, detections=[Mock()], commit_id=commit_id)],
    )


def test_get_document_detections_matches_commit_document_by_archived_name() -> None:
    # commit range documents are archived as '<commit_id>/<path>' and the server reports that name back
    commit_id = 'a' * 40
    document = Document(os.path.join(os.sep, 'repo', 'creds.txt'), 'content', unique_id=commit_id)
    scan_result = _scan_result_for(concat_unique_id(document.path, commit_id), commit_id)

    document_detections = _get_document_detections(scan_result, [document])

    assert document_detections[0].document is document


def test_get_document_detections_keeps_detection_when_document_is_not_found() -> None:
    scan_result = _scan_result_for('unknown.txt', 'a' * 40)

    document_detections = _get_document_detections(scan_result, [])

    assert document_detections[0].document.path == 'unknown.txt'
    assert len(document_detections[0].detections) == 1
