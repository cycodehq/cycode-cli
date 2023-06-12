import abc
from typing import List, NamedTuple, Dict, Optional

import click
from texttable import Texttable

from cycode.cli.consts import SECRET_SCAN_TYPE, INFRA_CONFIGURATION_SCAN_TYPE, SAST_SCAN_TYPE
from cycode.cli.printers.text_printer import TextPrinter
from cycode.cli.models import DocumentDetections, CliError, CliResult
from cycode.cli.printers.base_printer import BasePrinter


class ColumnInfo(NamedTuple):
    name: str
    index: int  # lower index means left column
    width_secret: int = 1
    width_sast: int = 1
    width_iac: int = 1


class Table:
    """Helper class to manage columns and their values in the right order and only if the column should be presented."""

    def __init__(self, scan_type: str, columns_info: Optional[List[ColumnInfo]] = None):
        self.scan_type = scan_type

        self._columns: Dict[ColumnInfo, List[str]] = dict()
        if columns_info:
            self._columns: Dict[ColumnInfo, List[str]] = {columns: list() for columns in columns_info}

    def add(self, column: ColumnInfo):
        self._columns[column] = list()

    def set(self, column: ColumnInfo, value: str):
        # we push values only for existing columns what were added before
        if column in self._columns:
            self._columns[column].append(value)

    def _get_ordered_columns(self) -> List[ColumnInfo]:
        # we are sorting columns by index to make sure that columns will be printed in the right order
        return sorted(self._columns, key=lambda column_info: column_info.index)

    def get_columns_info(self) -> List[ColumnInfo]:
        return self._get_ordered_columns()

    def get_headers(self) -> List[str]:
        return [header.name for header in self._get_ordered_columns()]

    def get_rows(self) -> List[str]:
        ordered_values = [self._columns[column_info] for column_info in self._get_ordered_columns()]
        return list(zip(*ordered_values))

    def _get_table_columns_width(self) -> List[int]:
        header_width_size_cols = []
        for header in self.get_columns_info():
            width_multiplier = 1
            if self.scan_type == SECRET_SCAN_TYPE:
                width_multiplier = header.width_secret
            elif self.scan_type == INFRA_CONFIGURATION_SCAN_TYPE:
                width_multiplier = header.width_iac
            elif self.scan_type == SAST_SCAN_TYPE:
                width_multiplier = header.width_sast

            header_width_size_cols.append(len(header.name) * width_multiplier)

        return header_width_size_cols

    def get_table(self, max_width: int = 80) -> Texttable:
        table = Texttable(max_width)
        table.header(self.get_headers())

        for row in self.get_rows():
            table.add_row(row)

        table.set_cols_width(self._get_table_columns_width())

        return table


class BaseTablePrinter(BasePrinter, abc.ABC):
    def __init__(self, context: click.Context):
        super().__init__(context)
        self.context = context
        self.scan_id: str = context.obj.get('scan_id')
        self.scan_type: str = context.obj.get('scan_type')
        self.show_secret: bool = context.obj.get('show_secret', False)

    def print_result(self, result: CliResult) -> None:
        TextPrinter(self.context).print_result(result)

    def print_error(self, error: CliError) -> None:
        TextPrinter(self.context).print_error(error)

    def print_scan_results(self, results: List[DocumentDetections]):
        click.secho(f'Scan Results: (scan_id: {self.scan_id})')

        if not results:
            click.secho('Good job! No issues were found!!! 👏👏👏', fg=self.GREEN_COLOR_NAME)
            return

        self._print_results(results)

        report_url = self.context.obj.get('report_url')
        if report_url:
            click.secho(f'Report URL: {report_url}')

    def _is_git_repository(self) -> bool:
        return self.context.obj.get('remote_url') is not None

    @abc.abstractmethod
    def _print_results(self, results: List[DocumentDetections]) -> None:
        raise NotImplementedError
