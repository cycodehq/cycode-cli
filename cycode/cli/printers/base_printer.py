from abc import ABC, abstractmethod
from typing import List

import click

from cycode.cli.models import DocumentDetections, CliResult, CliError


class BasePrinter(ABC):
    RED_COLOR_NAME = 'red'
    WHITE_COLOR_NAME = 'white'
    GREEN_COLOR_NAME = 'green'

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
