from typing import NamedTuple


class ColumnInfo(NamedTuple):
    name: str
    index: int  # Represents the order of the columns, starting from the left
    width_secret: int = 1
    width_sast: int = 1
    width_iac: int = 1
