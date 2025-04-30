import abc
from typing import TYPE_CHECKING, Optional

from cycode.cli.models import CliError, CliResult
from cycode.cli.printers.printer_base import PrinterBase
from cycode.cli.printers.text_printer import TextPrinter

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult
    from cycode.cli.printers.tables.table import Table


class TablePrinterBase(PrinterBase, abc.ABC):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.text_printer = TextPrinter(self.ctx, self.console, self.console_err)

    def print_result(self, result: CliResult) -> None:
        self.text_printer.print_result(result)

    def print_error(self, error: CliError) -> None:
        self.text_printer.print_error(error)

    def print_scan_results(
        self, local_scan_results: list['LocalScanResult'], errors: Optional[dict[str, 'CliError']] = None
    ) -> None:
        if not errors and all(result.issue_detected == 0 for result in local_scan_results):
            self.console.print(self.NO_DETECTIONS_MESSAGE)
            return

        self._print_results(local_scan_results)

        self.print_scan_results_summary(local_scan_results)
        self.text_printer.print_report_urls_and_errors(local_scan_results, errors)

    @abc.abstractmethod
    def _print_results(self, local_scan_results: list['LocalScanResult']) -> None:
        raise NotImplementedError

    def _print_table(self, table: 'Table') -> None:
        if table.get_rows():
            self.console.print(table.get_table())
