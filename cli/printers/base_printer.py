import click
from abc import ABC, abstractmethod
from typing import List
from cli.models import DocumentDetections


class BasePrinter(ABC):

    context: click.Context

    def __init__(self, context: click.Context):
        self.context = context

    @abstractmethod
    def print_results(self, results: List[DocumentDetections]):
        pass
