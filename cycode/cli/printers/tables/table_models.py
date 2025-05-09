from typing import NamedTuple, Optional


class ColumnInfoBuilder:
    def __init__(self) -> None:
        self._index = 0

    def build(self, name: str, **column_opts) -> 'ColumnInfo':
        column_info = ColumnInfo(name, self._index, column_opts)
        self._index += 1
        return column_info


class ColumnInfo(NamedTuple):
    name: str
    index: int  # Represents the order of the columns, starting from the left
    column_opts: Optional[dict] = None

    def __hash__(self) -> int:
        return hash((self.name, self.index))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ColumnInfo):
            return NotImplemented
        return (self.name, self.index) == (other.name, other.index)
