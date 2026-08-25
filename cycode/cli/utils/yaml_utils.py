import os
import tempfile
from collections.abc import Hashable
from typing import Any, TextIO

import yaml

from cycode.logger import get_logger

logger = get_logger('YAML Utils')


def _deep_update(source: dict[Hashable, Any], overrides: dict[Hashable, Any]) -> dict[Hashable, Any]:
    for key, value in overrides.items():
        if isinstance(value, dict) and value:
            source[key] = _deep_update(source.get(key, {}), value)
        else:
            source[key] = overrides[key]

    return source


def _yaml_object_safe_load(file: TextIO) -> dict[Hashable, Any]:
    # loader.get_single_data could return None
    loaded_file = yaml.safe_load(file)

    if not isinstance(loaded_file, dict):
        # forbid literals at the top level
        logger.debug(
            'YAML file does not contain a dictionary at the top level: %s',
            {'filename': file.name, 'actual_type': type(loaded_file)},
        )
        return {}

    return loaded_file


def _quarantine_corrupt_file(filename: str) -> None:
    # Renamed rather than deleted: the file may hold the only copy of the user's credentials,
    # and keeping it around leaves something to look at in the next bug report.
    try:
        os.replace(filename, f'{filename}.corrupt')
    except OSError as e:
        logger.warning('Failed to quarantine corrupt file, %s', {'filename': filename}, exc_info=e)


def read_yaml_file(filename: str) -> dict[Hashable, Any]:
    if not os.access(filename, os.R_OK) or not os.path.exists(filename):
        logger.debug('Config file is not accessible or does not exist: %s', {'filename': filename})
        return {}

    try:
        with open(filename, encoding='UTF-8') as file:
            return _yaml_object_safe_load(file)
    except yaml.YAMLError as e:
        logger.warning('Config file is corrupt and will be moved aside, %s', {'filename': filename}, exc_info=e)
        _quarantine_corrupt_file(filename)
        return {}


def write_yaml_file(filename: str, content: dict[Hashable, Any]) -> None:
    directory = os.path.dirname(filename)
    if not os.access(directory, os.W_OK) or (os.path.exists(filename) and not os.access(filename, os.W_OK)):
        logger.warning('No write permission for file. Cannot save config, %s', {'filename': filename})
        return

    # Atomic write to avoid race conditions between concurrent CLI processes
    file_descriptor, temp_filename = tempfile.mkstemp(dir=directory, prefix=f'.{os.path.basename(filename)}.')
    try:
        with os.fdopen(file_descriptor, 'w', encoding='UTF-8') as file:
            yaml.safe_dump(content, file)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_filename, filename)
    except Exception:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
        raise


def update_yaml_file(filename: str, content: dict[Hashable, Any]) -> None:
    write_yaml_file(filename, _deep_update(read_yaml_file(filename), content))
