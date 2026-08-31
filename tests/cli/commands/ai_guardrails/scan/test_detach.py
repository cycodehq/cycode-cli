"""Tests for the report-mode self-detach mechanism."""

import subprocess
import sys
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from cycode.cli.apps.ai_guardrails.scan.detach import (
    DETACHED_ENV_VAR,
    build_respawn_command,
    is_detached_child,
    respawn_detached,
)


def test_is_detached_child_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DETACHED_ENV_VAR, raising=False)
    assert is_detached_child() is False

    monkeypatch.setenv(DETACHED_ENV_VAR, '1')
    assert is_detached_child() is True


def test_build_respawn_command_script_install(monkeypatch: pytest.MonkeyPatch) -> None:
    """pip install: sys.executable is python, argv[0] is the console script to re-run."""
    monkeypatch.delattr(sys, 'frozen', raising=False)
    monkeypatch.setattr(sys, 'argv', ['/usr/local/bin/cycode', 'ai-guardrails', 'scan', '--ide', 'cursor'])

    assert build_respawn_command() == [
        sys.executable,
        '/usr/local/bin/cycode',
        'ai-guardrails',
        'scan',
        '--ide',
        'cursor',
    ]


def test_build_respawn_command_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    """PyInstaller: sys.executable is the CLI binary itself; argv[0] is dropped."""
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'argv', ['cycode', 'ai-guardrails', 'scan', '--ide', 'cursor'])

    assert build_respawn_command() == [sys.executable, 'ai-guardrails', 'scan', '--ide', 'cursor']


def _mock_popen(mocker: MockerFixture) -> MagicMock:
    popen = mocker.patch('cycode.cli.apps.ai_guardrails.scan.detach.subprocess.Popen')
    popen.return_value.pid = 4242
    return popen


def test_respawn_detached_hands_over_payload_with_fresh_handles(mocker: MockerFixture) -> None:
    popen = _mock_popen(mocker)

    assert respawn_detached('{"prompt": "hi"}') is True

    kwargs = popen.call_args.kwargs
    # Fresh handles are the whole point: the child must not inherit the IDE's
    # pipes, or EOF-waiting hook runners block for the scan's full duration.
    assert kwargs['stdin'] == subprocess.PIPE
    assert kwargs['stdout'] == subprocess.DEVNULL
    assert kwargs['stderr'] == subprocess.DEVNULL
    assert kwargs['env'][DETACHED_ENV_VAR] == '1'
    if sys.platform == 'win32':
        assert kwargs['creationflags'] != 0
    else:
        assert kwargs['start_new_session'] is True

    child_stdin = popen.return_value.stdin
    child_stdin.write.assert_called_once_with(b'{"prompt": "hi"}')
    child_stdin.close.assert_called_once_with()
    popen.return_value.wait.assert_not_called()


def test_respawn_detached_failure_returns_false(mocker: MockerFixture) -> None:
    mocker.patch('cycode.cli.apps.ai_guardrails.scan.detach.subprocess.Popen', side_effect=OSError('spawn failed'))

    assert respawn_detached('{}') is False
