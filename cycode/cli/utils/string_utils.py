import hashlib
import math
import random
import re
import string
from sys import getsizeof

from binaryornot.check import is_binary_string

from cycode.cli.consts import SCA_SHORTCUT_DEPENDENCY_PATHS


def obfuscate_text(text: str) -> str:
    match_len = len(text)
    start_reveled_len = math.ceil(match_len / 8)
    end_reveled_len = match_len - (math.ceil(match_len / 8))

    obfuscated = obfuscate_regex.sub('*', text)

    return f'{text[:start_reveled_len]}{obfuscated[start_reveled_len:end_reveled_len]}{text[end_reveled_len:]}'


obfuscate_regex = re.compile(r'[^+\-\s]')


def is_binary_content(content: str) -> bool:
    """Get the first 1024 chars and check if it's binary or not."""
    chunk = content[:1024]
    chunk_bytes = convert_string_to_bytes(chunk)
    return is_binary_string(chunk_bytes)


def get_content_size(content: str) -> int:
    return getsizeof(content)


def convert_string_to_bytes(content: str) -> bytes:
    return bytes(content, 'UTF-8')


def hash_string_to_sha256(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def generate_random_string(string_len: int) -> str:
    # letters, digits, and symbols
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(string_len))  # noqa: S311


def get_position_in_line(text: str, position: int) -> int:
    return position - text.rfind('\n', 0, position) - 1


def shortcut_dependency_paths(dependency_paths_list: str) -> str:
    separate_dependency_paths_list = dependency_paths_list.split(',')
    result = ''
    for dependency_paths in separate_dependency_paths_list:
        dependency_paths = dependency_paths.strip().rstrip()
        dependencies = dependency_paths.split(' -> ')
        if len(dependencies) <= SCA_SHORTCUT_DEPENDENCY_PATHS:
            result += dependency_paths
        else:
            result += f'{dependencies[0]} -> ... -> {dependencies[-1]}'
        result += '\n\n'

    return result.rstrip().rstrip(',')
