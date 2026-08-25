from unittest.mock import MagicMock, patch

import pytest

from cycode.cli.apps.scan.scan_parameters import _get_default_scan_parameters, get_scan_parameters


@pytest.fixture
def mock_context() -> MagicMock:
    """Create a mock typer.Context for testing."""
    ctx = MagicMock()
    ctx.obj = {
        'monitor': False,
        'report': False,
        'package-vulnerabilities': True,
        'license-compliance': True,
    }
    ctx.info_name = 'test-command'
    return ctx


def test_get_default_scan_parameters(mock_context: MagicMock) -> None:
    """Test that default scan parameters are correctly extracted from context."""
    params = _get_default_scan_parameters(mock_context)

    assert params['monitor'] is False
    assert params['report'] is False
    assert params['package_vulnerabilities'] is True
    assert params['license_compliance'] is True
    assert params['command_type'] == 'test_command'  # hyphens replaced with underscores
    assert 'aggregation_id' in params


def test_get_scan_parameters_without_paths(mock_context: MagicMock) -> None:
    """Test get_scan_parameters returns only default params when no paths provided."""
    params = get_scan_parameters(mock_context)

    assert 'paths' not in params
    assert 'remote_url' not in params
    assert 'branch' not in params
    assert params['monitor'] is False


@patch('cycode.cli.apps.scan.scan_parameters.get_remote_url_scan_parameter')
def test_get_scan_parameters_with_paths(mock_get_remote_url: MagicMock, mock_context: MagicMock) -> None:
    """Test get_scan_parameters includes paths and remote_url when paths provided."""
    mock_get_remote_url.return_value = 'https://github.com/example/repo.git'
    paths = ('/path/to/repo',)

    params = get_scan_parameters(mock_context, paths)

    assert params['paths'] == paths
    assert params['remote_url'] == 'https://github.com/example/repo.git'
    assert mock_context.obj['remote_url'] == 'https://github.com/example/repo.git'


@patch('cycode.cli.apps.scan.scan_parameters.get_remote_url_scan_parameter')
def test_get_scan_parameters_includes_branch_when_set(mock_get_remote_url: MagicMock, mock_context: MagicMock) -> None:
    """Test that branch is included in scan_parameters when set in context."""
    mock_get_remote_url.return_value = None
    mock_context.obj['branch'] = 'feature-branch'
    paths = ('/path/to/repo',)

    params = get_scan_parameters(mock_context, paths)

    assert params['branch'] == 'feature-branch'


@patch('cycode.cli.apps.scan.scan_parameters.get_remote_url_scan_parameter')
def test_get_scan_parameters_excludes_branch_when_not_set(
    mock_get_remote_url: MagicMock, mock_context: MagicMock
) -> None:
    """Test that branch is not included in scan_parameters when not set in context."""
    mock_get_remote_url.return_value = None
    # Ensure branch is not in context
    mock_context.obj.pop('branch', None)
    paths = ('/path/to/repo',)

    params = get_scan_parameters(mock_context, paths)

    assert 'branch' not in params


@patch('cycode.cli.apps.scan.scan_parameters.get_remote_url_scan_parameter')
def test_get_scan_parameters_excludes_branch_when_none(mock_get_remote_url: MagicMock, mock_context: MagicMock) -> None:
    """Test that branch is not included when explicitly set to None."""
    mock_get_remote_url.return_value = None
    mock_context.obj['branch'] = None
    paths = ('/path/to/repo',)

    params = get_scan_parameters(mock_context, paths)

    assert 'branch' not in params


@patch('cycode.cli.apps.scan.scan_parameters.get_remote_url_scan_parameter')
def test_get_scan_parameters_branch_with_various_names(mock_get_remote_url: MagicMock, mock_context: MagicMock) -> None:
    """Test branch parameter works with various branch naming conventions."""
    mock_get_remote_url.return_value = None
    paths = ('/path/to/repo',)

    # Test main branch
    mock_context.obj['branch'] = 'main'
    params = get_scan_parameters(mock_context, paths)
    assert params['branch'] == 'main'

    # Test feature branch with slashes
    mock_context.obj['branch'] = 'feature/add-new-functionality'
    params = get_scan_parameters(mock_context, paths)
    assert params['branch'] == 'feature/add-new-functionality'

    # Test branch with special characters
    mock_context.obj['branch'] = 'release-v1.0.0'
    params = get_scan_parameters(mock_context, paths)
    assert params['branch'] == 'release-v1.0.0'
