import abc
from typing import TYPE_CHECKING, Dict, List, Optional

import click

from cycode.cli.models import CliError, CliResult
from cycode.cli.printers.printer_base import PrinterBase
from cycode.cli.printers.text_printer import TextPrinter

if TYPE_CHECKING:
    from cycode.cli.models import LocalScanResult
    from cycode.cli.printers.tables.table import Table


class TablePrinterBase(PrinterBase, abc.ABC):
    def __init__(self, context: click.Context) -> None:
        super().__init__(context)
        self.scan_type: str = context.obj.get('scan_type')
        self.show_secret: bool = context.obj.get('show_secret', False)

    def print_result(self, result: CliResult) -> None:
        TextPrinter(self.context).print_result(result)

    def print_error(self, error: CliError) -> None:
        TextPrinter(self.context).print_error(error)

    def print_scan_results(
        self, local_scan_results: List['LocalScanResult'], errors: Optional[Dict[str, 'CliError']] = None
    ) -> None:
        if not errors and all(result.issue_detected == 0 for result in local_scan_results):
            click.secho('Good job! No issues were found!!! 👏👏👏', fg=self.GREEN_COLOR_NAME)
            return

        self._print_results(local_scan_results)

        if not errors:
            return

        click.secho(
            'Unfortunately, Cycode was unable to complete the full scan. '
            'Please note that not all results may be available:',
            fg='red',
        )
        for scan_id, error in errors.items():
            click.echo(f'- {scan_id}: ', nl=False)
            self.print_error(error)

    def _is_git_repository(self) -> bool:
        return self.context.obj.get('remote_url') is not None

    @abc.abstractmethod
    def _print_results(self, local_scan_results: List['LocalScanResult']) -> None:
        raise NotImplementedError

    @staticmethod
    def _print_table(table: 'Table') -> None:
        if table.get_rows():
            click.echo(table.get_table().draw())
