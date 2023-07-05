from typing import Dict, NamedTuple


class ColumnInfoBuilder:
    _index = 0

    @staticmethod
    def build(name: str) -> 'ColumnInfo':
        column_info = ColumnInfo(name, ColumnInfoBuilder._index)
        ColumnInfoBuilder._index += 1
        return column_info


class ColumnInfo(NamedTuple):
    name: str
    index: int  # Represents the order of the columns, starting from the left


ColumnWidths = Dict[ColumnInfo, int]
ColumnWidthsConfig = Dict[str, ColumnWidths]
