import click
from typing import List

from cycode.cli.consts import SCA_SCAN_TYPE
from cycode.cli.printers import JsonPrinter, TextPrinter
from cycode.cli.models import DocumentDetections
from cycode.cli.printers.table_printer import TablePrinter


class ResultsPrinter:
    printers = {
        'text': TextPrinter,
        'json': JsonPrinter,
        'text_sca': TablePrinter
    }

    def print_results(self, context: click.Context, detections_results_list: List[DocumentDetections],
                      output_type: str):
        printer = self.get_printer(output_type, context)
        printer.print_results(detections_results_list)

    def get_printer(self, output_type: str, context: click.Context):
        scan_type = context.obj.get('scan_type')
        printer = TablePrinter if scan_type is not None and scan_type == SCA_SCAN_TYPE and output_type == 'text' \
            else self.printers.get(output_type)

        if not printer:
            raise ValueError(f'the provided output is not supported - {output_type}')

        return printer(context)
