from abc import ABC, abstractmethod
from typing import List

import click

from cycode.cli.models import DocumentDetections, CliResult, CliError


class BasePrinter(ABC):
    context: click.Context

    def __init__(self, context: click.Context):
        self.context = context

    @abstractmethod
    def print_scan_results(self, results: List[DocumentDetections]) -> None:
        pass

    @abstractmethod
    def print_result(self, result: CliResult) -> None:
        pass

    @abstractmethod
    def print_error(self, error: CliError) -> None:
        pass
