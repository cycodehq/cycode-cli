import click
from abc import ABC, abstractmethod
from typing import List
from cli.models import DocumentDetections
from cyclient import models


class BasePrinter(ABC):

    context: click.Context

    def __init__(self, context: click.Context):
        self.context = context

    @abstractmethod
    def print_results(self, context: click.Context, results: List[DocumentDetections]):
        pass

    @abstractmethod
    def print_scan_details(self, scan_details_response: models.ScanDetailsResponse):
        pass
