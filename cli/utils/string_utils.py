import math
import re
import hashlib
from sys import getsizeof
from binaryornot.check import is_binary_string

def obfuscate_text(text: str) -> str:
    match_len = len(text)
    start_reveled_len = math.ceil(match_len / 8)
    end_reveled_len = match_len - (math.ceil(match_len / 8))

    obfuscated = obfuscate_regex.sub("*", text)

    return f'{text[:start_reveled_len]}{obfuscated[start_reveled_len:end_reveled_len]}{text[end_reveled_len:]}'


obfuscate_regex = re.compile(r"[^+\-\s]")


"""
get the first 1024 chars and check if its binary or not
"""
def is_binary_content(content: str):
    chunk = content[:1024]
    chunk_bytes = convert_string_to_bytes(chunk)
    return is_binary_string(chunk_bytes)


def get_content_size(content: str):
    return getsizeof(content)


def convert_string_to_bytes(content: str):
    return bytes(content, 'utf-8')


def convert_string_to_sha256(content: str):
    return hashlib.sha256(content.encode()).hexdigest()
