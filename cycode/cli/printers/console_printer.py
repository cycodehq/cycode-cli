import click
from typing import List, TYPE_CHECKING

from cycode.cli.consts import SCA_SCAN_TYPE
from cycode.cli.exceptions.custom_exceptions import CycodeError
from cycode.cli.models import DocumentDetections, CliResult, CliError
from cycode.cli.printers.table_printer import TablePrinter
from cycode.cli.printers.json_printer import JsonPrinter
from cycode.cli.printers.text_printer import TextPrinter

if TYPE_CHECKING:
    from cycode.cli.printers.base_printer import BasePrinter


class ConsolePrinter:
    _AVAILABLE_PRINTERS = {
        'text': TextPrinter,
        'json': JsonPrinter,
        'text_sca': TablePrinter
    }

    def __init__(self, context: click.Context):
        self.context = context
        self.output_type = self.context.obj.get('output')

        self._printer_class = self._AVAILABLE_PRINTERS.get(self.output_type)
        if self._printer_class is None:
            raise CycodeError(f'"{self.output_type}" output type is not supported.')

    def print_scan_results(self, detections_results_list: List[DocumentDetections]) -> None:
        printer = self._get_scan_printer()
        printer.print_scan_results(detections_results_list)

    def _get_scan_printer(self) -> 'BasePrinter':
        scan_type = self.context.obj.get('scan_type')

        printer_class = self._printer_class
        if scan_type == SCA_SCAN_TYPE and self.output_type == 'text':
            printer_class = TablePrinter

        return printer_class(self.context)

    def print_result(self, result: CliResult) -> None:
        self._printer_class(self.context).print_result(result)

    def print_error(self, error: CliError) -> None:
        self._printer_class(self.context).print_error(error)
