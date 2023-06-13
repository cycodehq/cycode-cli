import abc
from typing import List

import click

from cycode.cli.printers.text_printer import TextPrinter
from cycode.cli.models import DocumentDetections, CliError, CliResult
from cycode.cli.printers.base_printer import BasePrinter


class BaseTablePrinter(BasePrinter, abc.ABC):
    def __init__(self, context: click.Context):
        super().__init__(context)
        self.context = context
        self.scan_id: str = context.obj.get('scan_id')
        self.scan_type: str = context.obj.get('scan_type')
        self.show_secret: bool = context.obj.get('show_secret', False)

    def print_result(self, result: CliResult) -> None:
        TextPrinter(self.context).print_result(result)

    def print_error(self, error: CliError) -> None:
        TextPrinter(self.context).print_error(error)

    def print_scan_results(self, results: List[DocumentDetections]):
        click.secho(f'Scan Results: (scan_id: {self.scan_id})')

        if not results:
            click.secho('Good job! No issues were found!!! 👏👏👏', fg=self.GREEN_COLOR_NAME)
            return

        self._print_results(results)

        report_url = self.context.obj.get('report_url')
        if report_url:
            click.secho(f'Report URL: {report_url}')

    def _is_git_repository(self) -> bool:
        return self.context.obj.get('remote_url') is not None

    @abc.abstractmethod
    def _print_results(self, results: List[DocumentDetections]) -> None:
        raise NotImplementedError
