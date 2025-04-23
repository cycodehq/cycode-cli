import abc
from typing import TYPE_CHECKING, Dict, List, Optional

import typer

from cycode.cli.models import CliError, CliResult
from cycode.cli.printers.printer_base import PrinterBase
from cycode.cli.printers.text_printer import TextPrinter

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult
    from cycode.cli.printers.tables.table import Table


class TablePrinterBase(PrinterBase, abc.ABC):
    def __init__(self, ctx: typer.Context, *args, **kwargs) -> None:
        super().__init__(ctx, *args, **kwargs)
        self.scan_type: str = ctx.obj.get('scan_type')
        self.show_secret: bool = ctx.obj.get('show_secret', False)

    def print_result(self, result: CliResult) -> None:
        TextPrinter(self.ctx).print_result(result)

    def print_error(self, error: CliError) -> None:
        TextPrinter(self.ctx).print_error(error)

    def print_scan_results(
        self, local_scan_results: List['LocalScanResult'], errors: Optional[Dict[str, 'CliError']] = None
    ) -> None:
        if not errors and all(result.issue_detected == 0 for result in local_scan_results):
            self.console.print(self.NO_DETECTIONS_MESSAGE)
            return

        self._print_results(local_scan_results)

        if not errors:
            return

        self.console.print(self.FAILED_SCAN_MESSAGE)
        for scan_id, error in errors.items():
            self.console.print(f'- {scan_id}: ', end='')
            self.print_error(error)

    def _is_git_repository(self) -> bool:
        return self.ctx.info_name in {'commit_history', 'pre_commit', 'pre_receive'} and 'remote_url' in self.ctx.obj

    @abc.abstractmethod
    def _print_results(self, local_scan_results: List['LocalScanResult']) -> None:
        raise NotImplementedError

    def _print_table(self, table: 'Table') -> None:
        if table.get_rows():
            self.console.print(table.get_table())

    def _print_report_urls(
        self,
        local_scan_results: List['LocalScanResult'],
        aggregation_report_url: Optional[str] = None,
    ) -> None:
        report_urls = [scan_result.report_url for scan_result in local_scan_results if scan_result.report_url]
        if not report_urls and not aggregation_report_url:
            return
        if aggregation_report_url:
            self.console.print(f'Report URL: {aggregation_report_url}')
            return

        self.console.print('Report URLs:')
        for report_url in report_urls:
            self.console.print(f'- {report_url}')
