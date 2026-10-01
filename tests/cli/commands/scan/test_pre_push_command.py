from io import StringIO
from unittest.mock import MagicMock, Mock, patch

import pytest

from cycode.cli import consts
from cycode.cli.apps.scan.pre_push.pre_push_command import pre_push_command

_PRE_COMMIT_ENV_VARS = (
    consts.PRE_COMMIT_FRAMEWORK_ENV_VAR_NAME,
    consts.PRE_COMMIT_FROM_REF_ENV_VAR_NAME,
    consts.PRE_COMMIT_TO_REF_ENV_VAR_NAME,
    consts.PRE_COMMIT_REMOTE_BRANCH_ENV_VAR_NAME,
)


@pytest.fixture(autouse=True)
def _clean_pre_commit_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for env_var_name in _PRE_COMMIT_ENV_VARS:
        monkeypatch.delenv(env_var_name, raising=False)


def _make_ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.info_name = consts.PRE_PUSH_COMMAND_SCAN_TYPE
    ctx.obj = {'console_printer': MagicMock(), 'progress_bar': MagicMock()}
    return ctx


def _run_pre_push(ctx: MagicMock, stdin: str) -> None:
    with patch('sys.stdin', StringIO(stdin)):
        pre_push_command(ctx)


@patch('cycode.cli.apps.scan.pre_push.pre_push_command.scan_commit_range')
def test_scans_push_range_provided_by_pre_commit_framework(
    mock_scan_commit_range: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the framework consumes git's stdin; the hook gets empty stdin and the refs via env vars
    monkeypatch.setenv(consts.PRE_COMMIT_FRAMEWORK_ENV_VAR_NAME, '1')
    monkeypatch.setenv(consts.PRE_COMMIT_FROM_REF_ENV_VAR_NAME, 'a' * 40)
    monkeypatch.setenv(consts.PRE_COMMIT_TO_REF_ENV_VAR_NAME, 'b' * 40)
    monkeypatch.setenv(consts.PRE_COMMIT_REMOTE_BRANCH_ENV_VAR_NAME, 'refs/heads/main')

    ctx = _make_ctx()
    _run_pre_push(ctx, '')

    mock_scan_commit_range.assert_called_once()
    assert mock_scan_commit_range.call_args.kwargs['commit_range'] == f'{"a" * 40}..{"b" * 40}'
    assert not ctx.obj.get('did_fail')


@patch('cycode.cli.apps.scan.pre_push.pre_push_command.scan_commit_range')
def test_scans_all_commits_when_pre_commit_framework_pushes_root_commit(
    mock_scan_commit_range: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the framework omits the refs when the pushed history includes the root commit
    monkeypatch.setenv(consts.PRE_COMMIT_FRAMEWORK_ENV_VAR_NAME, '1')
    monkeypatch.setenv(consts.PRE_COMMIT_REMOTE_BRANCH_ENV_VAR_NAME, 'refs/heads/main')

    _run_pre_push(_make_ctx(), '')

    mock_scan_commit_range.assert_called_once()
    assert mock_scan_commit_range.call_args.kwargs['commit_range'] == consts.COMMIT_RANGE_ALL_COMMITS


@patch('cycode.cli.apps.scan.pre_push.pre_push_command.scan_commit_range')
def test_fails_closed_when_pre_commit_framework_gives_no_push_details(
    mock_scan_commit_range: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(consts.PRE_COMMIT_FRAMEWORK_ENV_VAR_NAME, '1')

    ctx = _make_ctx()
    _run_pre_push(ctx, '')

    mock_scan_commit_range.assert_not_called()
    assert ctx.obj['did_fail'] is True
    error = ctx.obj['console_printer'].print_error.call_args.args[0]
    assert error.code == 'pre_push_input_not_found'
    assert error.soft_fail is False


@patch('cycode.cli.apps.scan.pre_push.pre_push_command.scan_commit_range')
def test_scans_push_range_from_git_stdin(mock_scan_commit_range: Mock) -> None:
    ctx = _make_ctx()
    _run_pre_push(ctx, f'refs/heads/main {"b" * 40} refs/heads/main {"a" * 40}')

    mock_scan_commit_range.assert_called_once()
    assert mock_scan_commit_range.call_args.kwargs['commit_range'] == f'{"a" * 40}..{"b" * 40}'


@pytest.mark.parametrize(
    'stdin',
    [
        # git runs the hook with empty input when everything is up-to-date
        '',
        f'refs/tags/v1.0.0 {"b" * 40} refs/tags/v1.0.0 {consts.EMPTY_COMMIT_SHA}',
        f'(delete) {consts.EMPTY_COMMIT_SHA} refs/heads/feature {"a" * 40}',
    ],
)
@patch('cycode.cli.apps.scan.pre_push.pre_push_command.scan_commit_range')
def test_passes_quietly_when_git_push_has_nothing_to_scan(mock_scan_commit_range: Mock, stdin: str) -> None:
    ctx = _make_ctx()
    _run_pre_push(ctx, stdin)

    mock_scan_commit_range.assert_not_called()
    assert not ctx.obj.get('did_fail')
