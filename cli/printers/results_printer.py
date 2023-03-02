import click
from typing import List
from cli.printers import JsonPrinter, TextPrinter
from cli.models import DocumentDetections
from cyclient import models


class ResultsPrinter:
    printers = {
        'text': TextPrinter,
        'json': JsonPrinter
    }

    def print_results(self, context: click.Context, detections_results_list: List[DocumentDetections],
                      output_type: str):
        printer = self.get_printer(output_type, context)
        printer.print_results(detections_results_list)

    def print_scan_status(self, context: click.Context, scan_details_response: models.ScanDetailsResponse, output_type: str):
        printer = self.get_printer(output_type, context)
        printer.print_scan_status(scan_details_response)

    def get_printer(self, output_type: str, context: click.Context):
        printer = self.printers.get(output_type)
        if not printer:
            raise ValueError(f'the provided output is not supported - {output_type}')

        return printer(context)

