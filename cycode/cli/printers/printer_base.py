import sys
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Dict, List, Optional

import typer

from cycode.cli.models import CliError, CliResult
from cycode.cyclient.headers import get_correlation_id

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult


from rich.console import Console
from rich.traceback import Traceback


class PrinterBase(ABC):
    RED_COLOR_NAME = 'red'
    GREEN_COLOR_NAME = 'green'

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

    def print_exception(self, e: Optional[BaseException] = None) -> None:
        """We are printing it in stderr so, we don't care about supporting JSON and TABLE outputs.

        Note:
            Called only when the verbose flag is set.
        """
        console = Console(stderr=True)

        traceback = Traceback.from_exception(type(e), e, None) if e else Traceback.from_exception(*sys.exc_info())
        console.print(traceback)

        console.print(f'Correlation ID: {get_correlation_id()}', style=self.RED_COLOR_NAME)
