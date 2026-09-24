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


class TestScanLocalDiff:
    """Test the scan_local_diff dispatcher."""

    def _make_ctx(self, scan_type: str) -> MagicMock:
        mock_ctx = MagicMock()
        mock_ctx.obj = {'scan_type': scan_type, 'progress_bar': MagicMock()}
        return mock_ctx

    def test_unsupported_scan_type_raises(self) -> None:
        import click
        import pytest

        from cycode.cli.apps.scan.commit_range_scanner import scan_local_diff

        mock_ctx = self._make_ctx(consts.IAC_SCAN_TYPE)

        with pytest.raises(click.ClickException, match='IAC'):
            scan_local_diff(mock_ctx, repo_path='/repo', commit_rev='HEAD')

    def test_dispatches_secret_scan_type(self) -> None:
        from cycode.cli.apps.scan import commit_range_scanner
        from cycode.cli.apps.scan.commit_range_scanner import scan_local_diff

        mock_handler = Mock()
        with patch.dict(commit_range_scanner._SCAN_TYPE_TO_LOCAL_DIFF_HANDLER, {consts.SECRET_SCAN_TYPE: mock_handler}):
            mock_ctx = self._make_ctx(consts.SECRET_SCAN_TYPE)
            scan_local_diff(mock_ctx, repo_path='/repo', commit_rev='abc123', paths=['/repo/file.py'])

        mock_handler.assert_called_once_with(mock_ctx, '/repo', 'abc123', paths=['/repo/file.py'])

    def test_dispatches_sca_scan_type(self) -> None:
        from cycode.cli.apps.scan import commit_range_scanner
        from cycode.cli.apps.scan.commit_range_scanner import scan_local_diff

        mock_handler = Mock()
        with patch.dict(commit_range_scanner._SCAN_TYPE_TO_LOCAL_DIFF_HANDLER, {consts.SCA_SCAN_TYPE: mock_handler}):
            mock_ctx = self._make_ctx(consts.SCA_SCAN_TYPE)
            scan_local_diff(mock_ctx, repo_path='/repo', commit_rev='HEAD')

        mock_handler.assert_called_once_with(mock_ctx, '/repo', 'HEAD', paths=None)

    def test_dispatches_sast_scan_type(self) -> None:
        from cycode.cli.apps.scan import commit_range_scanner
        from cycode.cli.apps.scan.commit_range_scanner import scan_local_diff

        mock_handler = Mock()
        with patch.dict(commit_range_scanner._SCAN_TYPE_TO_LOCAL_DIFF_HANDLER, {consts.SAST_SCAN_TYPE: mock_handler}):
            mock_ctx = self._make_ctx(consts.SAST_SCAN_TYPE)
            scan_local_diff(mock_ctx, repo_path='/repo', commit_rev='HEAD')

        mock_handler.assert_called_once_with(mock_ctx, '/repo', 'HEAD', paths=None)
