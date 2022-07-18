import click
from typing import List
from cli.printers import JsonPrinter, TextPrinter
from cli.models import DocumentDetections


# TODO naming
class ResultsPrinter:
    printers = {
        'text': TextPrinter(),
        'json': JsonPrinter()
    }

    def print_results(self, context: click.Context, detections_results_list: List[DocumentDetections],
                      output_type: str):
        printer = self.get_printer(output_type)
        printer.print_results(context, detections_results_list)

    def get_printer(self, output_type: str):
        printer = self.printers.get(output_type)
        if not printer:
            # TODO throw exception
            pass

        return printer
