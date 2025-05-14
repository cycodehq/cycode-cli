import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import TYPE_CHECKING, Optional

import typer

from cycode.cli.cli_types import SeverityOption
from cycode.cli.models import CliError, CliResult
from cycode.cyclient.headers import get_correlation_id

if TYPE_CHECKING:
    from rich.console import Console

    from cycode.cli.models import LocalScanResult


from rich.traceback import Traceback as RichTraceback


class PrinterBase(ABC):
    NO_DETECTIONS_MESSAGE = (
        '[b green]Good job! No issues were found!!! :clapping_hands::clapping_hands::clapping_hands:[/]'
    )
    FAILED_SCAN_MESSAGE = (
        '[b red]Unfortunately, Cycode was unable to complete the full scan. '
        'Please note that not all results may be available:[/]'
    )

    def __init__(
        self,
        ctx: typer.Context,
        console: 'Console',
        console_err: 'Console',
    ) -> None:
        self.ctx = ctx
        self.console = console
        self.console_err = console_err

    @property
    def scan_type(self) -> str:
        return self.ctx.obj.get('scan_type')

    @property
    def command_scan_type(self) -> str:
        return self.ctx.info_name

    @property
    def show_secret(self) -> bool:
        return self.ctx.obj.get('show_secret', False)

    @abstractmethod
    def print_scan_results(
        self, local_scan_results: list['LocalScanResult'], errors: Optional[dict[str, 'CliError']] = None
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
        rich_traceback = (
            RichTraceback.from_exception(type(e), e, e.__traceback__)
            if e
            else RichTraceback.from_exception(*sys.exc_info())
        )
        rich_traceback.show_locals = False
        self.console_err.print(rich_traceback)

        self.console_err.print(f'[red]Correlation ID:[/] {get_correlation_id()}')

    def print_scan_results_summary(self, local_scan_results: list['LocalScanResult']) -> None:
        """Print a summary of scan results based on severity levels.

        Args:
            local_scan_results (List['LocalScanResult']): A list of local scan results containing detections.

        The summary includes the count of detections for each severity level
        and is displayed in the console in a formatted string.

        """
        detections_count = 0
        severity_counts = defaultdict(int)
        for local_scan_result in local_scan_results:
            for document_detections in local_scan_result.document_detections:
                for detection in document_detections.detections:
                    if detection.severity:
                        detections_count += 1
                        severity_counts[SeverityOption(detection.severity)] += 1

        self.console.line()
        self.console.print(f'[bold]Cycode found {detections_count} violations[/]', end=': ')

        # Example of string: CRITICAL - 6 | HIGH - 0 | MEDIUM - 14 | LOW - 0 | INFO - 0
        for index, severity in enumerate(reversed(SeverityOption), start=1):
            end = ' | '
            if index == len(SeverityOption):
                end = '\n'

            self.console.print(
                SeverityOption.get_member_emoji(severity), severity, '-', severity_counts[severity], end=end
            )

        self.console.line()
