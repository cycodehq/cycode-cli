from typing import Dict, NamedTuple


class ColumnInfoBuilder:
    def __init__(self) -> None:
        self._index = 0

    def build(self, name: str) -> 'ColumnInfo':
        column_info = ColumnInfo(name, self._index)
        self._index += 1
        return column_info


class ColumnInfo(NamedTuple):
    name: str
    index: int  # Represents the order of the columns, starting from the left


ColumnWidths = Dict[ColumnInfo, int]
ColumnWidthsConfig = Dict[str, ColumnWidths]
