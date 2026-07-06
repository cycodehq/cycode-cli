from unittest.mock import MagicMock, Mock, patch

from cycode.cli import consts
from cycode.cli.apps.scan.commit_range_scanner import _scan_commit_range_documents
from cycode.cli.exceptions import custom_exceptions
from cycode.cli.models import Document


@patch('cycode.cli.apps.scan.commit_range_scanner.report_scan_status')
@patch('cycode.cli.apps.scan.commit_range_scanner.handle_scan_exception')
@patch('cycode.cli.apps.scan.commit_range_scanner.print_local_scan_results')
@patch('cycode.cli.apps.scan.commit_range_scanner.set_issue_detected_by_scan_results')
@patch('cycode.cli.apps.scan.commit_range_scanner.create_local_scan_result')
@patch('cycode.cli.apps.scan.commit_range_scanner.enrich_scan_result_with_data_from_detection_rules')
@patch('cycode.cli.apps.scan.commit_range_scanner.zip_documents')
@patch('cycode.cli.apps.scan.commit_range_scanner._perform_commit_range_scan_async')
@patch('cycode.cli.apps.scan.commit_range_scanner._perform_commit_range_scan_v4_async')
def test_commit_range_scan_falls_back_to_api_when_presigned_upload_raises_wrapped_error(
    mock_v4_async: Mock,
    mock_async: Mock,
    mock_zip: Mock,
    mock_enrich: Mock,
    mock_create_result: Mock,
    mock_set_issue: Mock,
    mock_print: Mock,
    mock_handle_exception: Mock,
    mock_report_status: Mock,
) -> None:
    # SlowUploadConnectionError is a CycodeError, not a requests.RequestException — the presigned
    # commit-range fallback must still catch it and retry via the Cycode API.
    mock_v4_async.side_effect = custom_exceptions.SlowUploadConnectionError
    fallback_result = MagicMock()
    mock_async.return_value = fallback_result

    mock_ctx = MagicMock()
    mock_ctx.info_name = 'commit_history'
    mock_ctx.obj = {
        'client': MagicMock(),
        'scan_type': consts.SECRET_SCAN_TYPE,
        'severity_threshold': None,
        'progress_bar': MagicMock(),
    }
    documents = [Document('/repo/file.py', 'content', is_git_diff_format=False)]

    _scan_commit_range_documents(mock_ctx, documents, [])

    mock_v4_async.assert_called_once()
    mock_async.assert_called_once()
    mock_handle_exception.assert_not_called()
