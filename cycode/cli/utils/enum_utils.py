from enum import Enum
from typing import List


class AutoCountEnum(Enum):
    @staticmethod
    def _generate_next_value_(name: str, start: int, count: int, last_values: List[int]) -> int:
        return count
