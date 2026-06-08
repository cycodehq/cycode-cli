"""Tests for the argv-peek lazy subapp registration in cycode/cli/app.py.

The argv-peek picks the invoked subapp from sys.argv before Typer dispatches,
so it has to walk argv itself — skipping flags and (importantly) the values
those flags consume. The `_ROOT_OPTS_WITH_VALUE` set lists every root-level
flag that consumes a following positional token. If a maintainer adds a new
value-taking option to `app_callback` and forgets to register it here, the
argv-peek will silently fall back to the cold path (loading every subapp).
The test below catches that drift by comparing the hand-maintained set
against what Click's introspection sees on the built command.
"""

from typing import Optional
from unittest.mock import patch

import click
import pytest
import typer.main

from cycode.cli.app import _ROOT_OPTS_WITH_VALUE, _detect_invocation, app


def test_root_opts_with_value_matches_click_introspection() -> None:
    """Every root option that takes a value must be registered in _ROOT_OPTS_WITH_VALUE."""
    cmd = typer.main.get_command(app)
    expected = {
        opt
        for param in cmd.params
        if isinstance(param, click.Option) and not param.is_flag
        for opt in param.opts
        if opt.startswith('-')
    }
    assert frozenset(expected) == _ROOT_OPTS_WITH_VALUE, (
        f'_ROOT_OPTS_WITH_VALUE is out of sync with app_callback.\n'
        f'  Missing: {sorted(expected - _ROOT_OPTS_WITH_VALUE)}\n'
        f'  Extra:   {sorted(_ROOT_OPTS_WITH_VALUE - expected)}\n'
        f'Update _ROOT_OPTS_WITH_VALUE in cycode/cli/app.py.'
    )


@pytest.mark.parametrize(
    'argv',
    [
        ['cycode', 'ai-guardrails', 'scan'],
        ['cycode', '-v', 'ai-guardrails', 'scan'],
        ['cycode', '--verbose', 'ai-guardrails', 'scan'],
        ['cycode', '--output', 'json', 'ai-guardrails', 'scan'],
        ['cycode', '-o', 'json', 'ai-guardrails', 'scan'],
        ['cycode', '--user-agent', '{"app_name":"x"}', 'ai-guardrails', 'scan'],
        ['cycode', '--client-secret', 'secret-val', 'ai-guardrails', 'scan'],
        ['cycode', '--client-id', 'client-val', 'ai-guardrails', 'scan'],
        ['cycode', '--id-token', 'token-val', 'ai-guardrails', 'scan'],
        ['cycode', '--show-completion', 'bash', 'ai-guardrails', 'scan'],
        # --key=value form is one token; argv-peek should treat it as a flag
        ['cycode', '--output=json', 'ai-guardrails', 'scan'],
        # multiple value-taking options stacked
        ['cycode', '-v', '--output', 'json', '--client-id', 'foo', 'ai-guardrails', 'scan'],
    ],
)
def test_detect_invocation_finds_subcommand_past_flags(argv: list[str]) -> None:
    with patch('sys.argv', argv):
        assert _detect_invocation() == ('ai-guardrails', 'scan')


@pytest.mark.parametrize(
    ('argv', 'expected'),
    [
        # No positional args → no match
        (['cycode'], (None, None)),
        (['cycode', '-v'], (None, None)),
        # Unknown subapp → no match (graceful: app.py falls back to cold path)
        (['cycode', 'not-a-real-subapp'], (None, None)),
        # Known subapp, no subcommand
        (['cycode', 'scan'], ('scan', None)),
        # Alias resolution
        (['cycode', 'ai_remediation'], ('ai-remediation', None)),
        (['cycode', 'version'], ('status', None)),
    ],
)
def test_detect_invocation_edge_cases(argv: list[str], expected: tuple[Optional[str], Optional[str]]) -> None:
    with patch('sys.argv', argv):
        assert _detect_invocation() == expected
