from pathlib import Path
from unittest.mock import MagicMock

import pytest
import typer

from cycode.cli.utils.path_utils import get_path_from_context, get_scan_roots_from_context


def _ctx(params: dict) -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.params = params
    return ctx


class TestGetPathFromContextDelegates:
    """Both lookups read the same parameters, so they must not drift apart."""

    @pytest.mark.parametrize(
        ('command', 'params'),
        [
            ('scan path', {'paths': [Path('/repo/a')]}),
            ('scan repository', {'path': Path('/repo/a')}),
            ('report sbom path', {'path': Path('/repo/a')}),
        ],
    )
    def test_it_returns_the_first_scan_root_as_a_string(self, command: str, params: dict) -> None:
        """It is annotated Optional[str] but used to hand back the PosixPath typer produced."""
        result = get_path_from_context(_ctx(params))

        assert result == str(Path('/repo/a')), command
        assert isinstance(result, str), command

    def test_an_empty_paths_list_returns_none(self) -> None:
        """Indexing [0] used to raise IndexError here."""
        assert get_path_from_context(_ctx({'paths': []})) is None

    def test_it_agrees_with_the_full_scan_root_list(self) -> None:
        params = {'paths': [Path('/repo/a'), Path('/repo/b')]}

        assert get_path_from_context(_ctx(params)) == get_scan_roots_from_context(_ctx(params))[0]

    def test_no_parameters_returns_none(self) -> None:
        assert get_path_from_context(_ctx({})) is None
        assert get_path_from_context(MagicMock(spec=typer.Context)) is None
