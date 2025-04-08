import sys
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Dict, List, Optional

import typer

from cycode.cli.console import console_err
from cycode.cli.models import CliError, CliResult
from cycode.cyclient.headers import get_correlation_id

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult


from rich.traceback import Traceback as RichTraceback


class PrinterBase(ABC):
    NO_DETECTIONS_MESSAGE = (
        '[green]Good job! No issues were found!!! :clapping_hands::clapping_hands::clapping_hands:[/]'
    )
    FAILED_SCAN_MESSAGE = (
        '[red]Unfortunately, Cycode was unable to complete the full scan. '
        'Please note that not all results may be available:[/]'
    )

    def __init__(self, ctx: typer.Context) -> None:
        self.ctx = ctx

    @abstractmethod
    def print_scan_results(
        self, local_scan_results: List['LocalScanResult'], errors: Optional[Dict[str, 'CliError']] = None
    ) -> None:
        pass

    @abstractmethod
    def print_result(self, result: CliResult) -> None:
        pass

    @abstractmethod
    def print_error(self, error: CliError) -> None:
        pass

    @staticmethod
    def print_exception(e: Optional[BaseException] = None) -> None:
        """We are printing it in stderr so, we don't care about supporting JSON and TABLE outputs.

        Note:
            Called only when the verbose flag is set.
        """
        rich_traceback = (
            RichTraceback.from_exception(type(e), e, e.__traceback__)
            if e
            else RichTraceback.from_exception(*sys.exc_info())
        )
        rich_traceback.show_locals = False
        console_err.print(rich_traceback)

        console_err.print(f'[red]Correlation ID:[/] {get_correlation_id()}')
