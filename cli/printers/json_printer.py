import click
from typing import List
from cli.printers.base_printer import BasePrinter
from cli.models import DocumentDetections, Detection, Document


class JsonPrinter(BasePrinter):
    def print_results(self, context: click.Context, results: List[DocumentDetections]):
        pass
