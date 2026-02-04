"""Tests for AI guardrails scan command."""

import json
from io import StringIO
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture
from typer.testing import CliRunner

from cycode.cli.apps.ai_guardrails import app as ai_guardrails_app
from cycode.cli.apps.ai_guardrails.scan.scan_command import scan_command


@pytest.fixture
def mock_ctx() -> MagicMock:
    """Create a mock typer context."""
    ctx = MagicMock()
    ctx.obj = {}
    return ctx


@pytest.fixture
def mock_scan_command_deps(mocker: MockerFixture) -> dict[str, MagicMock]:
    """Mock scan_command dependencies that should not be called on early exit."""
    return {
        'initialize_clients': mocker.patch('cycode.cli.apps.ai_guardrails.scan.scan_command._initialize_clients'),
        'load_policy': mocker.patch('cycode.cli.apps.ai_guardrails.scan.scan_command.load_policy'),
        'get_handler': mocker.patch('cycode.cli.apps.ai_guardrails.scan.scan_command.get_handler_for_event'),
    }


def _assert_no_api_calls(mocks: dict[str, MagicMock]) -> None:
    """Assert that no API-related functions were called."""
    mocks['initialize_clients'].assert_not_called()
    mocks['load_policy'].assert_not_called()
    mocks['get_handler'].assert_not_called()


class TestIdeMismatchSkipsProcessing:
    """Tests that verify IDE mismatch causes early exit without API calls."""

    def test_claude_code_payload_with_cursor_ide(
        self,
        mock_ctx: MagicMock,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
        mock_scan_command_deps: dict[str, MagicMock],
    ) -> None:
        """Test Claude Code payload is skipped when --ide cursor is specified.

        When Cursor reads Claude Code hooks from ~/.claude/settings.json, it will invoke
        the hook with Claude Code event names. The scan command should skip processing.
        """
        payload = {'hook_event_name': 'UserPromptSubmit', 'session_id': 'session-123', 'prompt': 'test'}
        mocker.patch('sys.stdin', StringIO(json.dumps(payload)))

        scan_command(mock_ctx, ide='cursor')

        _assert_no_api_calls(mock_scan_command_deps)
        response = json.loads(capsys.readouterr().out)
        assert response.get('continue') is True

    def test_cursor_payload_with_claude_code_ide(
        self,
        mock_ctx: MagicMock,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
        mock_scan_command_deps: dict[str, MagicMock],
    ) -> None:
        """Test Cursor payload is skipped when --ide claude-code is specified."""
        payload = {'hook_event_name': 'beforeSubmitPrompt', 'conversation_id': 'conv-123', 'prompt': 'test'}
        mocker.patch('sys.stdin', StringIO(json.dumps(payload)))

        scan_command(mock_ctx, ide='claude-code')

        _assert_no_api_calls(mock_scan_command_deps)
        response = json.loads(capsys.readouterr().out)
        assert response == {}  # Claude Code allow_prompt returns empty dict


class TestInvalidPayloadSkipsProcessing:
    """Tests that verify invalid payloads cause early exit without API calls."""

    def test_empty_payload(
        self,
        mock_ctx: MagicMock,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
        mock_scan_command_deps: dict[str, MagicMock],
    ) -> None:
        """Test empty payload skips processing."""
        mocker.patch('sys.stdin', StringIO(''))

        scan_command(mock_ctx, ide='cursor')

        mock_scan_command_deps['initialize_clients'].assert_not_called()
        response = json.loads(capsys.readouterr().out)
        assert response.get('continue') is True

    def test_invalid_json_payload(
        self,
        mock_ctx: MagicMock,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
        mock_scan_command_deps: dict[str, MagicMock],
    ) -> None:
        """Test invalid JSON skips processing."""
        mocker.patch('sys.stdin', StringIO('not valid json {'))

        scan_command(mock_ctx, ide='cursor')

        mock_scan_command_deps['initialize_clients'].assert_not_called()
        response = json.loads(capsys.readouterr().out)
        assert response.get('continue') is True


class TestMatchingIdeProcessesPayload:
    """Tests that verify matching IDE processes the payload normally."""

    def test_claude_code_payload_with_claude_code_ide(
        self,
        mock_ctx: MagicMock,
        mocker: MockerFixture,
        mock_scan_command_deps: dict[str, MagicMock],
    ) -> None:
        """Test Claude Code payload is processed when --ide claude-code is specified."""
        payload = {'hook_event_name': 'UserPromptSubmit', 'session_id': 'session-123', 'prompt': 'test'}
        mocker.patch('sys.stdin', StringIO(json.dumps(payload)))

        mock_scan_command_deps['load_policy'].return_value = {'fail_open': True}
        mock_handler = MagicMock(return_value={'decision': 'allow'})
        mock_scan_command_deps['get_handler'].return_value = mock_handler

        scan_command(mock_ctx, ide='claude-code')

        mock_scan_command_deps['initialize_clients'].assert_called_once()
        mock_scan_command_deps['load_policy'].assert_called_once()
        mock_scan_command_deps['get_handler'].assert_called_once()
        mock_handler.assert_called_once()


class TestDefaultIdeParameterViaCli:
    """Tests that verify default IDE parameter works correctly via CLI invocation."""

    def test_scan_command_default_ide_via_cli(self, mocker: MockerFixture) -> None:
        """Test scan_command works with default --ide when invoked via CLI.

        This test catches issues where Typer converts enum defaults to strings
        incorrectly (e.g., AIIDEType.CURSOR becomes 'AIIDEType.CURSOR' instead of 'cursor').
        """
        mocker.patch('cycode.cli.apps.ai_guardrails.scan.scan_command._initialize_clients')
        mocker.patch(
            'cycode.cli.apps.ai_guardrails.scan.scan_command.load_policy',
            return_value={'fail_open': True},
        )
        mock_handler = MagicMock(return_value={'continue': True})
        mocker.patch(
            'cycode.cli.apps.ai_guardrails.scan.scan_command.get_handler_for_event',
            return_value=mock_handler,
        )

        runner = CliRunner()
        payload = json.dumps({'hook_event_name': 'beforeSubmitPrompt', 'prompt': 'test'})

        # Invoke via CLI without --ide flag to use default
        result = runner.invoke(ai_guardrails_app, ['scan'], input=payload)

        assert result.exit_code == 0, f'Command failed: {result.output}'
