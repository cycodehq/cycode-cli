import json
import os
import sys
from unittest.mock import AsyncMock, patch

import pytest

if sys.version_info < (3, 10):
    pytest.skip('MCP requires Python 3.10+', allow_module_level=True)

from cycode.cli.apps.mcp.mcp_command import (
    _sanitize_file_path,
    _TempFilesManager,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return 'asyncio'


# --- _sanitize_file_path input validation ---


def test_sanitize_file_path_rejects_empty_string() -> None:
    with pytest.raises(ValueError, match='non-empty string'):
        _sanitize_file_path('')


def test_sanitize_file_path_rejects_none() -> None:
    with pytest.raises(ValueError, match='non-empty string'):
        _sanitize_file_path(None)


def test_sanitize_file_path_rejects_non_string() -> None:
    with pytest.raises(ValueError, match='non-empty string'):
        _sanitize_file_path(123)


def test_sanitize_file_path_strips_null_bytes() -> None:
    result = _sanitize_file_path('foo/bar\x00baz.py')
    assert '\x00' not in result


def test_sanitize_file_path_passes_valid_path_through() -> None:
    result = _sanitize_file_path('src/main.py')
    assert os.path.normpath(result) == os.path.normpath('src/main.py')


# --- _TempFilesManager: path traversal prevention ---
#
# _sanitize_file_path delegates to pathvalidate which does NOT block
# path traversal (../ passes through). The real security boundary is
# the normpath containment check in _TempFilesManager.__enter__ (lines 136-139).
# These tests verify that the two layers together prevent escaping the temp dir.


def test_traversal_simple_dotdot_rejected() -> None:
    """../../../etc/passwd must not escape the temp directory."""
    files = {
        '../../../etc/passwd': 'malicious',
        'safe.py': 'ok',
    }
    with _TempFilesManager(files, 'test-traversal') as temp_files:
        assert len(temp_files) == 1
        assert temp_files[0].endswith('safe.py')
        for tf in temp_files:
            assert '/etc/passwd' not in tf


def test_traversal_backslash_dotdot_rejected() -> None:
    """..\\..\\windows\\system32 must not escape the temp directory."""
    files = {
        '..\\..\\windows\\system32\\config': 'malicious',
        'safe.py': 'ok',
    }
    with _TempFilesManager(files, 'test-backslash') as temp_files:
        assert len(temp_files) == 1
        assert temp_files[0].endswith('safe.py')


def test_traversal_embedded_dotdot_rejected() -> None:
    """foo/../../../etc/passwd resolves outside temp dir and must be rejected."""
    files = {
        'foo/../../../etc/passwd': 'malicious',
        'safe.py': 'ok',
    }
    with _TempFilesManager(files, 'test-embedded') as temp_files:
        assert len(temp_files) == 1
        assert temp_files[0].endswith('safe.py')


def test_traversal_absolute_path_rejected() -> None:
    """Absolute paths must not be written outside the temp directory."""
    files = {
        '/etc/passwd': 'malicious',
        'safe.py': 'ok',
    }
    with _TempFilesManager(files, 'test-absolute') as temp_files:
        assert len(temp_files) == 1
        assert temp_files[0].endswith('safe.py')


def test_traversal_dotdot_only_rejected() -> None:
    """A bare '..' path must be rejected."""
    files = {
        '..': 'malicious',
        'safe.py': 'ok',
    }
    with _TempFilesManager(files, 'test-bare-dotdot') as temp_files:
        assert len(temp_files) == 1


def test_traversal_all_malicious_raises() -> None:
    """If every file path is a traversal attempt, no files are created and ValueError is raised."""
    files = {
        '../../../etc/passwd': 'malicious',
        '../../shadow': 'also malicious',
    }
    with pytest.raises(ValueError, match='No valid files'), _TempFilesManager(files, 'test-all-malicious'):
        pass


def test_all_created_files_are_inside_temp_dir() -> None:
    """Every created file must be under the temp base directory."""
    files = {
        'a.py': 'aaa',
        'sub/b.py': 'bbb',
        'sub/deep/c.py': 'ccc',
    }
    manager = _TempFilesManager(files, 'test-containment')
    with manager as temp_files:
        base = os.path.normcase(os.path.normpath(manager.temp_base_dir))
        for tf in temp_files:
            normalized = os.path.normcase(os.path.normpath(tf))
            assert normalized.startswith(base + os.sep), f'{tf} escaped temp dir {base}'


def test_mixed_valid_and_traversal_only_creates_valid() -> None:
    """Valid files are created, traversal attempts are silently skipped."""
    files = {
        '../escape.py': 'bad',
        'legit.py': 'good',
        'foo/../../escape2.py': 'bad',
        'src/app.py': 'good',
    }
    manager = _TempFilesManager(files, 'test-mixed')
    with manager as temp_files:
        base = os.path.normcase(os.path.normpath(manager.temp_base_dir))
        assert len(temp_files) == 2
        for tf in temp_files:
            assert os.path.normcase(os.path.normpath(tf)).startswith(base + os.sep)
        basenames = [os.path.basename(tf) for tf in temp_files]
        assert 'legit.py' in basenames
        assert 'app.py' in basenames


# --- _TempFilesManager: general functionality ---


def test_temp_files_manager_creates_files() -> None:
    files = {
        'test1.py': 'print("hello")',
        'subdir/test2.js': 'console.log("world")',
    }
    with _TempFilesManager(files, 'test-call-id') as temp_files:
        assert len(temp_files) == 2
        for tf in temp_files:
            assert os.path.exists(tf)


def test_temp_files_manager_writes_correct_content() -> None:
    files = {'hello.py': 'print("hello world")'}
    with _TempFilesManager(files, 'test-content') as temp_files, open(temp_files[0]) as f:
        assert f.read() == 'print("hello world")'


def test_temp_files_manager_cleans_up_on_exit() -> None:
    files = {'cleanup.py': 'code'}
    manager = _TempFilesManager(files, 'test-cleanup')
    with manager as temp_files:
        temp_dir = manager.temp_base_dir
        assert os.path.exists(temp_dir)
        assert len(temp_files) == 1
    assert not os.path.exists(temp_dir)


def test_temp_files_manager_empty_path_raises() -> None:
    files = {'': 'empty path'}
    with pytest.raises(ValueError, match='No valid files'), _TempFilesManager(files, 'test-empty-path'):
        pass


def test_temp_files_manager_preserves_subdirectory_structure() -> None:
    files = {
        'src/main.py': 'main',
        'src/utils/helper.py': 'helper',
    }
    with _TempFilesManager(files, 'test-dirs') as temp_files:
        assert len(temp_files) == 2
        paths = [os.path.basename(tf) for tf in temp_files]
        assert 'main.py' in paths
        assert 'helper.py' in paths


# --- _run_cycode_command (async) ---


@pytest.mark.anyio
async def test_run_cycode_command_returns_dict() -> None:
    from cycode.cli.apps.mcp.mcp_command import _run_cycode_command

    mock_process = AsyncMock()
    mock_process.communicate.return_value = (b'', b'error output')
    mock_process.returncode = 1

    with patch('asyncio.create_subprocess_exec', return_value=mock_process):
        result = await _run_cycode_command('--invalid-flag-for-test')
    assert isinstance(result, dict)
    assert 'error' in result


@pytest.mark.anyio
async def test_run_cycode_command_parses_json_output() -> None:
    from cycode.cli.apps.mcp.mcp_command import _run_cycode_command

    mock_process = AsyncMock()
    mock_process.communicate.return_value = (b'{"status": "ok"}', b'')
    mock_process.returncode = 0

    with patch('asyncio.create_subprocess_exec', return_value=mock_process):
        result = await _run_cycode_command('version')
    assert result == {'status': 'ok'}


@pytest.mark.anyio
async def test_run_cycode_command_handles_invalid_json() -> None:
    from cycode.cli.apps.mcp.mcp_command import _run_cycode_command

    mock_process = AsyncMock()
    mock_process.communicate.return_value = (b'not json{', b'')
    mock_process.returncode = 0

    with patch('asyncio.create_subprocess_exec', return_value=mock_process):
        result = await _run_cycode_command('version')
    assert result['error'] == 'Failed to parse JSON output'


@pytest.mark.anyio
async def test_run_cycode_command_timeout() -> None:
    import asyncio

    from cycode.cli.apps.mcp.mcp_command import _run_cycode_command

    async def slow_communicate() -> tuple[bytes, bytes]:
        await asyncio.sleep(10)
        return b'', b''

    mock_process = AsyncMock()
    mock_process.communicate = slow_communicate

    with patch('asyncio.create_subprocess_exec', return_value=mock_process):
        result = await _run_cycode_command('status', timeout=0.001)
    assert isinstance(result, dict)
    assert 'error' in result
    assert 'timeout' in result['error'].lower()


# --- _cycode_scan_tool ---


@pytest.mark.anyio
async def test_cycode_scan_tool_no_files() -> None:
    from cycode.cli.apps.mcp.mcp_command import _cycode_scan_tool
    from cycode.cli.cli_types import ScanTypeOption

    result = await _cycode_scan_tool(ScanTypeOption.SECRET, {})
    parsed = json.loads(result)
    assert 'error' in parsed
    assert 'No files provided' in parsed['error']


@pytest.mark.anyio
async def test_cycode_scan_tool_invalid_files() -> None:
    from cycode.cli.apps.mcp.mcp_command import _cycode_scan_tool
    from cycode.cli.cli_types import ScanTypeOption

    result = await _cycode_scan_tool(ScanTypeOption.SECRET, {'': 'content'})
    parsed = json.loads(result)
    assert 'error' in parsed


# --- _create_mcp_server ---


def test_create_mcp_server() -> None:
    from cycode.cli.apps.mcp.mcp_command import _create_mcp_server

    server = _create_mcp_server('127.0.0.1', 8000)
    assert server is not None
    assert server.name == 'cycode'


def test_create_mcp_server_registers_tools() -> None:
    from cycode.cli.apps.mcp.mcp_command import _create_mcp_server

    server = _create_mcp_server('127.0.0.1', 8000)
    tool_names = [t.name for t in server._tool_manager._tools.values()]
    assert 'cycode_status' in tool_names
    assert 'cycode_secret_scan' in tool_names
    assert 'cycode_sca_scan' in tool_names
    assert 'cycode_iac_scan' in tool_names
    assert 'cycode_sast_scan' in tool_names
