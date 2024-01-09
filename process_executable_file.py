#!/usr/bin/env python3

"""
Used in the GitHub Actions workflow (build_executable.yml) to process the executable file.
This script calculates hash and renames executable file depending on the OS, arch, and build mode.
It also creates a file with the hash of the executable file.
It uses SHA256 algorithm to calculate the hash.
It returns the name of the executable file which is used as artifact name.
"""

import argparse
import hashlib
import os
import platform
from pathlib import Path
from string import Template
from typing import List, Tuple, Union

_HASH_FILE_EXT = '.sha256'
_OS_TO_CLI_DIST_TEMPLATE = {
    'darwin': Template('cycode-mac$suffix$ext'),
    'linux': Template('cycode-linux$suffix$ext'),
    'windows': Template('cycode-win$suffix.exe$ext'),
}
_WINDOWS = 'windows'
_WINDOWS_EXECUTABLE_SUFFIX = '.exe'

DirHashes = List[Tuple[str, str]]


def get_hash_of_file(file_path: Union[str, Path]) -> str:
    with open(file_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def get_hashes_of_many_files(root: str, file_paths: List[str]) -> DirHashes:
    hashes = []

    for file_path in file_paths:
        file_path = os.path.join(root, file_path)
        file_hash = get_hash_of_file(file_path)

        hashes.append((file_hash, file_path))

    return hashes


def get_hashes_of_every_file_in_the_directory(dir_path: Path) -> DirHashes:
    hashes = []

    for root, _, files in os.walk(dir_path):
        hashes.extend(get_hashes_of_many_files(root, files,))

    return hashes


def normalize_hashes_db(hashes: DirHashes, dir_path: Path) -> DirHashes:
    normalized_hashes = []

    for file_hash, file_path in hashes:
        relative_file_path = file_path[file_path.find(dir_path.name):]
        normalized_hashes.append((file_hash, relative_file_path))

    # sort by file path
    normalized_hashes.sort(key=lambda hash_item: hash_item[1])

    return normalized_hashes


def is_arm() -> bool:
    return platform.machine().lower() in ('arm', 'arm64', 'aarch64')


def get_os_name() -> str:
    return platform.system().lower()


def get_cli_file_name(suffix: str = '', ext: str = '') -> str:
    os_name = get_os_name()
    if os_name not in _OS_TO_CLI_DIST_TEMPLATE:
        raise Exception(f'Unsupported OS: {os_name}')

    template = _OS_TO_CLI_DIST_TEMPLATE[os_name]
    return template.substitute(suffix=suffix, ext=ext)


def get_cli_file_suffix(is_onedir: bool) -> str:
    suffixes = []

    if is_arm():
        suffixes.append('-arm')
    if is_onedir:
        suffixes.append('-onedir')

    return ''.join(suffixes)


def write_hash_to_file(file_hash: str, output_path: str) -> None:
    with open(output_path, 'w') as f:
        f.write(file_hash)


def write_hashes_db_to_file(hashes: DirHashes, output_path: str) -> None:
    content = ''
    for file_hash, file_path in hashes:
        content += f'{file_hash} {file_path}\n'

    with open(output_path, 'w') as f:
        f.write(content)


def get_cli_filename(is_onedir: bool) -> str:
    return get_cli_file_name(get_cli_file_suffix(is_onedir))


def get_cli_path(output_path: Path, is_onedir: bool) -> str:
    return os.path.join(output_path, get_cli_filename(is_onedir))


def get_cli_hash_filename(is_onedir: bool) -> str:
    return get_cli_file_name(suffix=get_cli_file_suffix(is_onedir), ext=_HASH_FILE_EXT)


def get_cli_hash_path(output_path: Path, is_onedir: bool) -> str:
    return os.path.join(output_path, get_cli_hash_filename(is_onedir))


def process_executable_file(input_path: Path, is_onedir: bool) -> str:
    output_path = input_path.parent
    hash_file_path = get_cli_hash_path(output_path, is_onedir)

    if is_onedir:
        hashes = get_hashes_of_every_file_in_the_directory(input_path)
        normalized_hashes = normalize_hashes_db(hashes, input_path)
        write_hashes_db_to_file(normalized_hashes, hash_file_path)
    else:
        file_hash = get_hash_of_file(input_path)
        write_hash_to_file(file_hash, hash_file_path)

        # for example rename cycode-cli to cycode-mac or cycode-mac-arm-onedir
        os.rename(input_path, get_cli_path(output_path, is_onedir))

    return get_cli_filename(is_onedir)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Path to executable or directory')

    args = parser.parse_args()
    input_path = Path(args.input)
    is_onedir = input_path.is_dir()

    if get_os_name() == _WINDOWS and not is_onedir and input_path.suffix != _WINDOWS_EXECUTABLE_SUFFIX:
        # add .exe on windows if was missed (to simplify GHA workflow)
        input_path = input_path.with_suffix(_WINDOWS_EXECUTABLE_SUFFIX)

    artifact_name = process_executable_file(input_path, is_onedir)

    print(artifact_name)  # noqa: T201


if __name__ == '__main__':
    main()
