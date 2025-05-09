import urllib.parse
from typing import TYPE_CHECKING, Optional

from rich.markup import escape
from rich.table import Table as RichTable

if TYPE_CHECKING:
    from cycode.cli.printers.tables.table_models import ColumnInfo


class Table:
    """Helper class to manage columns and their values in the right order and only if the column should be presented."""

    def __init__(self, column_infos: Optional[list['ColumnInfo']] = None) -> None:
        self._group_separator_indexes: set[int] = set()

        self._columns: dict[ColumnInfo, list[str]] = {}
        if column_infos:
            self._columns = {columns: [] for columns in column_infos}

    def add_column(self, column: 'ColumnInfo') -> None:
        self._columns[column] = []

    def _add_cell_no_error(self, column: 'ColumnInfo', value: str) -> None:
        # we push values only for existing columns what were added before
        if column in self._columns:
            self._columns[column].append(value)

    def add_cell(self, column: 'ColumnInfo', value: str, color: Optional[str] = None) -> None:
        if color:
            value = f'[{color}]{value}[/]'

        self._add_cell_no_error(column, value)

    def add_file_path_cell(self, column: 'ColumnInfo', path: str) -> None:
        encoded_path = urllib.parse.quote(path)
        escaped_path = escape(encoded_path)
        self._add_cell_no_error(column, f'[link file://{escaped_path}]{path}')

    def set_group_separator_indexes(self, group_separator_indexes: set[int]) -> None:
        self._group_separator_indexes = group_separator_indexes

    def _get_ordered_columns(self) -> list['ColumnInfo']:
        # we are sorting columns by index to make sure that columns will be printed in the right order
        return sorted(self._columns, key=lambda column_info: column_info.index)

    def get_columns_info(self) -> list['ColumnInfo']:
        return self._get_ordered_columns()

    def get_rows(self) -> list[str]:
        column_values = [self._columns[column_info] for column_info in self._get_ordered_columns()]
        return list(zip(*column_values))

    def get_table(self) -> 'RichTable':
        table = RichTable(expand=True, highlight=True)

        for column in self.get_columns_info():
            extra_args = column.column_opts if column.column_opts else {}
            table.add_column(header=column.name, overflow='fold', **extra_args)

        for index, raw in enumerate(self.get_rows()):
            table.add_row(*raw, end_section=index in self._group_separator_indexes)

        return table
