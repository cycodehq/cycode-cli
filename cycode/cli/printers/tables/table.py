from typing import TYPE_CHECKING, Dict, List, Optional

from texttable import Texttable

if TYPE_CHECKING:
    from cycode.cli.printers.tables.table_models import ColumnInfo, ColumnWidths


class Table:
    """Helper class to manage columns and their values in the right order and only if the column should be presented."""

    def __init__(self, column_infos: Optional[List['ColumnInfo']] = None) -> None:
        self._column_widths = None

        self._columns: Dict['ColumnInfo', List[str]] = {}
        if column_infos:
            self._columns: Dict['ColumnInfo', List[str]] = {columns: [] for columns in column_infos}

    def add(self, column: 'ColumnInfo') -> None:
        self._columns[column] = []

    def set(self, column: 'ColumnInfo', value: str) -> None:
        # we push values only for existing columns what were added before
        if column in self._columns:
            self._columns[column].append(value)

    def _get_ordered_columns(self) -> List['ColumnInfo']:
        # we are sorting columns by index to make sure that columns will be printed in the right order
        return sorted(self._columns, key=lambda column_info: column_info.index)

    def get_columns_info(self) -> List['ColumnInfo']:
        return self._get_ordered_columns()

    def get_headers(self) -> List[str]:
        return [header.name for header in self._get_ordered_columns()]

    def get_rows(self) -> List[str]:
        column_values = [self._columns[column_info] for column_info in self._get_ordered_columns()]
        return list(zip(*column_values))

    def set_cols_width(self, column_widths: 'ColumnWidths') -> None:
        header_width_size = []
        for header in self.get_columns_info():
            width_multiplier = 1
            if header in column_widths:
                width_multiplier = column_widths[header]

            header_width_size.append(len(header.name) * width_multiplier)

        self._column_widths = header_width_size

    def get_table(self, max_width: int = 80) -> Texttable:
        table = Texttable(max_width)
        table.header(self.get_headers())

        for row in self.get_rows():
            table.add_row(row)

        if self._column_widths:
            table.set_cols_width(self._column_widths)

        return table
