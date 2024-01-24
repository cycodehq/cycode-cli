from cycode.cli.utils.string_utils import hash_string_to_sha256

_SEPARATOR = '::'


def _get_hashed_creator(client_id: str, client_secret: str) -> str:
    return hash_string_to_sha256(_SEPARATOR.join([client_id, client_secret]))


class JwtCreator:
    def __init__(self, hashed_creator: str) -> None:
        self._hashed_creator = hashed_creator

    def __str__(self) -> str:
        return self._hashed_creator

    @classmethod
    def create(cls, client_id: str, client_secret: str) -> 'JwtCreator':
        return cls(_get_hashed_creator(client_id, client_secret))

    def __eq__(self, other: 'JwtCreator') -> bool:
        if not isinstance(other, JwtCreator):
            return NotImplemented
        return str(self) == str(other)
