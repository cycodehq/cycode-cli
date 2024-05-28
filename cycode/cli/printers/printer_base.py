import traceback
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Dict, List, Optional

import click

from cycode.cli.models import CliError, CliResult
from cycode.cyclient.headers import get_correlation_id

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult


class PrinterBase(ABC):
    RED_COLOR_NAME = 'red'
    WHITE_COLOR_NAME = 'white'
    GREEN_COLOR_NAME = 'green'

    def __init__(self, context: click.Context) -> None:
        self.context = context

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
        if e is None:
            # gets the most recent exception caught by an except clause
            message = f'Error: {traceback.format_exc()}'
        else:
            traceback_message = ''.join(traceback.format_exception(None, e, e.__traceback__))
            message = f'Error: {traceback_message}'

        click.secho(message, err=True, fg=self.RED_COLOR_NAME)

        correlation_message = f'Correlation ID: {get_correlation_id()}'
        click.secho(correlation_message, err=True, fg=self.RED_COLOR_NAME)
