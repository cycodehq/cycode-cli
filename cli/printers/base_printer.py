import click
from abc import ABC, abstractmethod
from typing import List
from cli.models import DocumentDetections


class BasePrinter(ABC):

    @abstractmethod
    def print_results(self, context: click.Context, results: List[DocumentDetections]):
        pass
