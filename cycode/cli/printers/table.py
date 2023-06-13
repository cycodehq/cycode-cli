from typing import List, Dict, Optional, TYPE_CHECKING
from texttable import Texttable

from cycode.cli.consts import SECRET_SCAN_TYPE, INFRA_CONFIGURATION_SCAN_TYPE, SAST_SCAN_TYPE

if TYPE_CHECKING:
    from cycode.cli.printers.column_info import ColumnInfo


class Table:
    """Helper class to manage columns and their values in the right order and only if the column should be presented."""

    def __init__(self, scan_type: str, column_infos: Optional[List['ColumnInfo']] = None):
        self.scan_type = scan_type

        self._columns: Dict['ColumnInfo', List[str]] = dict()
        if column_infos:
            self._columns: Dict['ColumnInfo', List[str]] = {columns: list() for columns in column_infos}

    def add(self, column: 'ColumnInfo'):
        self._columns[column] = list()

    def set(self, column: 'ColumnInfo', value: str):
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
