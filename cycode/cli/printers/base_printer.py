from abc import ABC, abstractmethod
from typing import List

import click

from cycode.cli.models import DocumentDetections


class BasePrinter(ABC):

    context: click.Context

    def __init__(self, context: click.Context):
        self.context = context

    @abstractmethod
    def print_results(self, results: List[DocumentDetections]):
        pass
